"""OpenAI Responses API backend for GPT-5.4 (reasoning.effort=low).

Converts the repository's chat-style messages/tools (used everywhere in the
agents) into Responses `input` items and `tools`, and normalizes the Responses
output back into a NormalizedModelTurn. This supports both the single-shot
CE-MCP synthesis call and the traditional multi-turn tool loop (assistant
tool_calls + tool outputs are mapped to function_call / function_call_output).
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from openai import OpenAI

from src.backends._transport import call_with_backoff
from src.backends.normalized_types import (
    NormalizedModelTurn,
    NormalizedToolCall,
    NormalizedUsage,
)


def _chat_tools_to_responses(tools: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for t in tools:
        fn = t.get("function", t)
        out.append(
            {
                "type": "function",
                "name": fn["name"],
                "description": fn.get("description", ""),
                "parameters": fn.get("parameters", {"type": "object", "properties": {}}),
            }
        )
    return out


def _chat_messages_to_responses_input(
    messages: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for m in messages:
        role = m.get("role")
        if role in ("system", "developer", "user"):
            items.append({"role": role, "content": m.get("content") or ""})
        elif role == "assistant":
            if m.get("content"):
                items.append({"role": "assistant", "content": m["content"]})
            for tc in m.get("tool_calls") or []:
                fn = tc["function"]
                items.append(
                    {
                        "type": "function_call",
                        "call_id": tc["id"],
                        "name": fn["name"],
                        "arguments": fn.get("arguments") or "{}",
                    }
                )
        elif role == "tool":
            items.append(
                {
                    "type": "function_call_output",
                    "call_id": m.get("tool_call_id"),
                    "output": m.get("content") or "",
                }
            )
    return items


def _parse_output(resp: Any) -> tuple[str | None, list[NormalizedToolCall], str | None]:
    text_parts: list[str] = []
    tool_calls: list[NormalizedToolCall] = []
    reasoning_summary: str | None = None

    # Prefer the SDK convenience if present.
    output_text = getattr(resp, "output_text", None)

    for item in getattr(resp, "output", []) or []:
        itype = getattr(item, "type", None)
        if itype == "message":
            for part in getattr(item, "content", []) or []:
                if getattr(part, "type", None) in ("output_text", "text"):
                    text_parts.append(getattr(part, "text", "") or "")
        elif itype == "function_call":
            raw_args = getattr(item, "arguments", "") or "{}"
            try:
                args = json.loads(raw_args)
            except json.JSONDecodeError:
                args = {"__raw_arguments__": raw_args}
            tool_calls.append(
                NormalizedToolCall(
                    call_id=getattr(item, "call_id", None) or getattr(item, "id", ""),
                    name=getattr(item, "name", ""),
                    arguments=args,
                )
            )
        elif itype == "reasoning":
            summary = getattr(item, "summary", None)
            if summary:
                try:
                    reasoning_summary = " ".join(
                        getattr(s, "text", "") for s in summary
                    ).strip() or None
                except Exception:  # noqa: BLE001
                    reasoning_summary = None

    text = output_text if output_text else ("\n".join(p for p in text_parts if p) or None)
    return text, tool_calls, reasoning_summary


class OpenAIResponsesBackend:
    def __init__(
        self,
        *,
        model_key: str,
        model: str,
        client: OpenAI,
        reasoning_effort: str = "low",
        store: bool = False,
        experiment_tag: str = "aidc_revision_2026",
    ) -> None:
        self.model_key = model_key
        self.model = model
        self.client = client
        self.reasoning_effort = reasoning_effort
        self.store = store
        self.experiment_tag = experiment_tag

    def generate(
        self,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]],
        *,
        max_output_tokens: int,
        request_metadata: Mapping[str, Any],
    ) -> NormalizedModelTurn:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "input": _chat_messages_to_responses_input(messages),
            "reasoning": {"effort": self.reasoning_effort},
            "store": self.store,
        }
        if max_output_tokens:
            kwargs["max_output_tokens"] = max_output_tokens
        if tools:
            kwargs["tools"] = _chat_tools_to_responses(tools)
            kwargs["tool_choice"] = "auto"
        metadata = {"experiment": self.experiment_tag}
        trial_id = request_metadata.get("trial_id")
        if trial_id:
            metadata["trial_id"] = str(trial_id)
        kwargs["metadata"] = metadata

        resp, retries = call_with_backoff(lambda: self.client.responses.create(**kwargs))

        text, tool_calls, reasoning_summary = _parse_output(resp)

        usage = getattr(resp, "usage", None)
        input_tokens = output_tokens = reasoning_tokens = cached_tokens = None
        if usage is not None:
            input_tokens = getattr(usage, "input_tokens", None)
            output_tokens = getattr(usage, "output_tokens", None)
            odetails = getattr(usage, "output_tokens_details", None)
            if odetails is not None:
                reasoning_tokens = getattr(odetails, "reasoning_tokens", None)
            idetails = getattr(usage, "input_tokens_details", None)
            if idetails is not None:
                cached_tokens = getattr(idetails, "cached_tokens", None)

        return NormalizedModelTurn(
            text=text,
            tool_calls=tool_calls,
            reasoning_summary=reasoning_summary,
            raw_model_name=getattr(resp, "model", self.model),
            request_id=getattr(resp, "_request_id", None) or getattr(resp, "id", None),
            usage=NormalizedUsage(
                input_tokens=int(input_tokens) if input_tokens is not None else None,
                output_tokens=int(output_tokens) if output_tokens is not None else None,
                reasoning_tokens=int(reasoning_tokens) if reasoning_tokens is not None else None,
                cached_input_tokens=int(cached_tokens) if cached_tokens is not None else None,
            ),
            transport_retry_count=retries,
            reasoning_mode="low",
            reasoning_control_source="api",
        )
