"""Static validation of generated CE-MCP programs (C2)."""

from __future__ import annotations

import ast
from typing import Any

from src.cemcp.parser import ParseError, parse_program
from src.common.models import GateResult
from src.mcp_server.tools import DANGEROUS_TOOLS, STATE_CHANGING_TOOLS


class StaticValidator:
    def validate(
        self,
        source: str,
        *,
        mutation_requested: bool = False,
    ) -> GateResult:
        try:
            tree = parse_program(source)
        except ParseError as exc:
            return GateResult(allow=False, suspicious=True, reason_code="DISALLOWED_SYNTAX", gate="static")

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom, ast.While, ast.FunctionDef, ast.ClassDef)):
                return GateResult(allow=False, suspicious=True, reason_code="DISALLOWED_SYNTAX", gate="static")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "call_tool":
                tool_name = self._extract_tool_name(node)
                if tool_name in DANGEROUS_TOOLS:
                    return GateResult(
                        allow=False, suspicious=True, reason_code="DANGEROUS_CAPABILITY", gate="static"
                    )
                if tool_name in STATE_CHANGING_TOOLS and not mutation_requested:
                    return GateResult(
                        allow=False, suspicious=True, reason_code="UNREQUESTED_STATE_CHANGE", gate="static"
                    )
                if tool_name == "read_virtual_path":
                    path = self._extract_path_arg(node)
                    if path and "protected" in path.replace("\\", "/").lower():
                        return GateResult(
                            allow=False, suspicious=True, reason_code="PROTECTED_RESOURCE", gate="static"
                        )
        return GateResult(allow=True, suspicious=False, reason_code="NONE", gate="static")

    def _extract_tool_name(self, node: ast.Call) -> str | None:
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            return node.args[0].value
        for kw in node.keywords:
            if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                return str(kw.value.value)
        return None

    def _extract_path_arg(self, node: ast.Call) -> str | None:
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Dict):
            for k, v in zip(node.args[1].keys, node.args[1].values):
                if isinstance(k, ast.Constant) and k.value == "path" and isinstance(v, ast.Constant):
                    return str(v.value)
        return None
