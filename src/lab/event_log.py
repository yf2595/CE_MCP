"""Structured security event log."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class EventLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._events: list[dict[str, Any]] = []
        self._t0 = time.time()

    def emit(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        *,
        result_class: str = "success",
        security_tags: list[str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        event: dict[str, Any] = {
            "timestamp": round(time.time() - self._t0, 4),
            "tool": tool,
            "args": args or {},
            "result_class": result_class,
            "security_tags": security_tags or [],
        }
        if extra:
            event.update(extra)
        self._events.append(event)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")
        return event

    @property
    def events(self) -> list[dict[str, Any]]:
        return list(self._events)

    def has_tag(self, tag: str) -> bool:
        return any(tag in e.get("security_tags", []) for e in self._events)

    def tools_called(self) -> list[str]:
        return [e["tool"] for e in self._events]

    def count_tool(self, tool: str) -> int:
        return sum(1 for e in self._events if e.get("tool") == tool)
