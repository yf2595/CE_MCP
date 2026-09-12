"""Per-trial model-call accounting.

Collects fields that the agents/gates don't otherwise surface (transport
retries, reasoning tokens, request IDs, returned model name, reasoning mode) so
the v2.0 log schema can be populated without modifying the agent loops.

Usage:
    with collect() as turns:
        result = agent.run(...)
    stats = summarize(turns)
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from src.backends.normalized_types import NormalizedModelTurn

_ACTIVE: contextvars.ContextVar[list[dict[str, Any]] | None] = contextvars.ContextVar(
    "backend_accounting_active", default=None
)


def record_turn(turn: NormalizedModelTurn) -> None:
    sink = _ACTIVE.get()
    if sink is None:
        return
    sink.append(
        {
            "transport_retry_count": turn.transport_retry_count,
            "reasoning_tokens": turn.usage.reasoning_tokens or 0,
            "cached_input_tokens": turn.usage.cached_input_tokens or 0,
            "input_tokens": turn.usage.input_tokens or 0,
            "output_tokens": turn.usage.output_tokens or 0,
            "request_id": turn.request_id,
            "raw_model_name": turn.raw_model_name,
            "reasoning_mode": turn.reasoning_mode,
            "reasoning_control_source": turn.reasoning_control_source,
        }
    )


@contextmanager
def collect() -> Iterator[list[dict[str, Any]]]:
    sink: list[dict[str, Any]] = []
    token = _ACTIVE.set(sink)
    try:
        yield sink
    finally:
        _ACTIVE.reset(token)


@dataclass
class TurnStats:
    transport_retry_count: int = 0
    reasoning_tokens: int = 0
    cached_input_tokens: int = 0
    model_call_count: int = 0
    request_ids: list[str] | None = None
    returned_model: str | None = None
    reasoning_mode: str | None = None
    reasoning_control_source: str | None = None


def summarize(turns: list[dict[str, Any]]) -> TurnStats:
    stats = TurnStats(request_ids=[])
    for t in turns:
        stats.transport_retry_count += int(t.get("transport_retry_count") or 0)
        stats.reasoning_tokens += int(t.get("reasoning_tokens") or 0)
        stats.cached_input_tokens += int(t.get("cached_input_tokens") or 0)
        stats.model_call_count += 1
        rid = t.get("request_id")
        if rid:
            stats.request_ids.append(rid)
        # First non-empty returned model / reasoning mode wins.
        if stats.returned_model is None and t.get("raw_model_name"):
            stats.returned_model = t["raw_model_name"]
        if stats.reasoning_mode is None and t.get("reasoning_mode"):
            stats.reasoning_mode = t["reasoning_mode"]
        if stats.reasoning_control_source is None and t.get("reasoning_control_source"):
            stats.reasoning_control_source = t["reasoning_control_source"]
    return stats
