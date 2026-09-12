"""Provider-agnostic normalized model I/O types (plan section 4.1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class NormalizedToolCall:
    call_id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class NormalizedUsage:
    input_tokens: int | None = None
    output_tokens: int | None = None
    reasoning_tokens: int | None = None
    cached_input_tokens: int | None = None


@dataclass
class NormalizedModelTurn:
    text: str | None
    tool_calls: list[NormalizedToolCall] = field(default_factory=list)
    reasoning_summary: str | None = None
    raw_model_name: str | None = None
    request_id: str | None = None
    usage: NormalizedUsage = field(default_factory=NormalizedUsage)
    raw_response: dict[str, Any] | None = None
    # Transport-layer accounting. Never conflate with agent regeneration.
    transport_retry_count: int = 0
    reasoning_mode: str | None = None
    reasoning_control_source: str | None = None
