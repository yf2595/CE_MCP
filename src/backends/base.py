"""Backend protocol + a ChatCompletion-compatible shim.

The shim lets legacy agents/gates keep consuming
`resp.choices[0].message.content` / `.tool_calls` and `usage_tokens(resp)`
without any changes, while backends internally produce `NormalizedModelTurn`.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from src.backends.normalized_types import NormalizedModelTurn


@runtime_checkable
class ModelBackend(Protocol):
    model_key: str

    def generate(
        self,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]],
        *,
        max_output_tokens: int,
        request_metadata: Mapping[str, Any],
    ) -> NormalizedModelTurn: ...


# --- ChatCompletion-compatible shim ---------------------------------------


class _ShimFunction:
    def __init__(self, name: str, arguments: str) -> None:
        self.name = name
        self.arguments = arguments


class _ShimToolCall:
    def __init__(self, call_id: str, name: str, arguments: str) -> None:
        self.id = call_id
        self.type = "function"
        self.function = _ShimFunction(name, arguments)


class _ShimMessage:
    def __init__(self, content: str | None, tool_calls: list[_ShimToolCall] | None) -> None:
        self.content = content
        self.tool_calls = tool_calls or None
        self.role = "assistant"


class _ShimChoice:
    def __init__(self, message: _ShimMessage) -> None:
        self.message = message
        self.finish_reason = "stop"


class _ShimUsage:
    def __init__(self, prompt_tokens: int, completion_tokens: int, reasoning_tokens: int) -> None:
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.total_tokens = prompt_tokens + completion_tokens
        self.reasoning_tokens = reasoning_tokens


class ChatCompletionShim:
    """Mimics the subset of openai ChatCompletion the agents rely on."""

    def __init__(self, turn: NormalizedModelTurn) -> None:
        self._turn = turn
        tool_calls = [
            _ShimToolCall(tc.call_id, tc.name, json.dumps(tc.arguments))
            for tc in turn.tool_calls
        ]
        message = _ShimMessage(turn.text, tool_calls)
        self.choices = [_ShimChoice(message)]
        self.model = turn.raw_model_name
        self.usage = _ShimUsage(
            int(turn.usage.input_tokens or 0),
            int(turn.usage.output_tokens or 0),
            int(turn.usage.reasoning_tokens or 0),
        )
        self._request_id = turn.request_id

    @property
    def normalized(self) -> NormalizedModelTurn:
        return self._turn
