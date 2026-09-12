"""Chat Completions backend.

Serves the retained legacy GPT-4.1 model (identical call to the pre-revision
code path) and, when pointed at a vLLM base_url, the local open-weight models
(see vllm_chat.py which configures per-model sampling on top of this).
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from openai import OpenAI

from src.backends._transport import call_with_backoff
from src.backends.normalized_types import (
    NormalizedModelTurn,
    NormalizedToolCall,
    NormalizedUsage,
)


class OpenAIChatBackend:
    def __init__(
        self,
        *,
        model_key: str,
        model: str,
        client: OpenAI,
        temperature: float | None = 0.0,
        extra_params: Mapping[str, Any] | None = None,
        reasoning_mode: str | None = None,
        reasoning_control_source: str | None = None,
        system_prefix: str | None = None,
    ) -> None:
        self.model_key = model_key
        self.model = model
        self.client = client
        self.temperature = temperature
        self.extra_params = dict(extra_params or {})
        self.reasoning_mode = reasoning_mode
        self.reasoning_control_source = reasoning_control_source
        # Model-level compatibility prefix (e.g. Llama plan-and-act, gpt-oss
        # "Reasoning: low"). Prepended as an extra system message; it must NOT
        # alter frozen task/attack/tool/defense text.
        self.system_prefix = system_prefix

    def generate(
        self,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]],
        *,
        max_output_tokens: int,
        request_metadata: Mapping[str, Any],
    ) -> NormalizedModelTurn:
        msg_list = list(messages)
        if self.system_prefix:
            msg_list = [{"role": "system", "content": self.system_prefix}, *msg_list]
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": msg_list,
        }
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        if tools:
            kwargs["tools"] = list(tools)
            kwargs["tool_choice"] = "auto"
        # max token param name differs across model families.
        token_param = self.extra_params.pop("_max_tokens_param", "max_tokens")
        if max_output_tokens:
            kwargs[token_param] = max_output_tokens
        # extra_body (top_k, chat_template_kwargs), seed, top_p, reasoning_effort...
        for k, v in self.extra_params.items():
            kwargs[k] = v

        resp, retries = call_with_backoff(lambda: self.client.chat.completions.create(**kwargs))

        msg = resp.choices[0].message
        tool_calls: list[NormalizedToolCall] = []
        for tc in msg.tool_calls or []:
            import json

            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {"__raw_arguments__": tc.function.arguments}
            tool_calls.append(NormalizedToolCall(tc.id, tc.function.name, args))

        usage = getattr(resp, "usage", None)
        reasoning_tokens = None
        if usage is not None:
            details = getattr(usage, "completion_tokens_details", None)
            if details is not None:
                reasoning_tokens = getattr(details, "reasoning_tokens", None)

        return NormalizedModelTurn(
            text=msg.content,
            tool_calls=tool_calls,
            raw_model_name=getattr(resp, "model", self.model),
            request_id=getattr(resp, "_request_id", None) or getattr(resp, "id", None),
            usage=NormalizedUsage(
                input_tokens=int(getattr(usage, "prompt_tokens", 0) or 0) if usage else None,
                output_tokens=int(getattr(usage, "completion_tokens", 0) or 0) if usage else None,
                reasoning_tokens=reasoning_tokens,
            ),
            transport_retry_count=retries,
            reasoning_mode=self.reasoning_mode,
            reasoning_control_source=self.reasoning_control_source,
        )
