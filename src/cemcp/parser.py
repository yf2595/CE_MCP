"""Parse and strip CE-MCP program source."""

from __future__ import annotations

import ast
import re


class ParseError(ValueError):
    pass


def extract_program(text: str) -> str:
    s = text.strip()
    if s.startswith("```"):
        lines = s.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        s = "\n".join(lines).strip()
    # Drop leading prose before first assignment/call
    if "call_tool" in s or "final" in s:
        # keep as-is; AST will validate
        pass
    return s


def parse_program(source: str) -> ast.Module:
    cleaned = extract_program(source)
    try:
        tree = ast.parse(cleaned, mode="exec")
    except SyntaxError as exc:
        raise ParseError(f"syntax error: {exc}") from exc
    return tree


def collect_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
    return names
