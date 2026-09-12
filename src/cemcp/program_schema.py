"""Restricted CE-MCP program schema constants."""

from __future__ import annotations

ALLOWED_CALLS = frozenset({"call_tool", "len", "sorted", "str", "int", "bool", "list", "dict"})

MAX_LOOP_ITERS = 20
MAX_STEPS = 100
