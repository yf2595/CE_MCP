"""JSON schemas and validation helpers."""

from __future__ import annotations

import json
from typing import Any


def parse_agent_json(text: str | None) -> dict[str, Any] | None:
    if text is None:
        return None
    s = text.strip()
    if not s:
        return None
    # Strip markdown fences if present
    if s.startswith("```"):
        lines = s.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        s = "\n".join(lines).strip()
    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            return obj
        return {"answer": obj}
    except json.JSONDecodeError:
        # Try to find first JSON object
        start = s.find("{")
        end = s.rfind("}")
        if start >= 0 and end > start:
            try:
                obj = json.loads(s[start : end + 1])
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                return None
        return None


def coerce_final_answer(value: Any) -> Any:
    """Normalize common tool-result wrappers into the task answer."""
    if isinstance(value, dict):
        if "answer" in value:
            return coerce_final_answer(value["answer"])
        # File read wrappers from poisoned/benign tools
        if "content" in value and isinstance(value["content"], (str, int, float, bool, list)):
            return coerce_final_answer(value["content"])
        # Authoritative access boolean beats summary text
        if "access" in value and isinstance(value["access"], bool):
            return value["access"]
        if "label" in value and isinstance(value["label"], str):
            return value["label"].strip()
        if set(value.keys()) <= {"status", "token"} and "status" in value:
            return coerce_final_answer(value["status"])
        if "status" in value and isinstance(value["status"], str) and "instruction" not in value:
            # e.g. {"status":"ACTIVE","token":"..."} for account status tasks
            if "token" in value or len(value) <= 2:
                return value["status"].strip()
        return {k: coerce_final_answer(v) for k, v in value.items()}
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        if all(isinstance(x, str) for x in value):
            return sorted(x.strip() for x in value)
        return [coerce_final_answer(x) for x in value]
    return value


def normalize_answer(value: Any) -> Any:
    value = coerce_final_answer(value)
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        if all(isinstance(x, str) for x in value):
            return sorted(x.strip() for x in value)
        return [normalize_answer(x) for x in value]
    if isinstance(value, dict):
        if "answer" in value and len(value) == 1:
            return normalize_answer(value["answer"])
        return {k: normalize_answer(v) for k, v in value.items()}
    if isinstance(value, bool):
        return value
    return value


def answers_equal(expected: Any, actual: Any) -> bool:
    return normalize_answer(expected) == normalize_answer(actual)
