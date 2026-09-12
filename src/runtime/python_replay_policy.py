"""Allowlist policy for CPython replay, mirroring the existing AST interpreter.

The policy is derived from src/cemcp/safe_executor.py + src/lab/safety_guard.py +
src/cemcp/program_schema.py. It must not be broadened just to make a generated
program execute. A program that is valid in the AST executor but rejected here is
classified as `policy_mismatch` (never silently modified).
"""

from __future__ import annotations

import ast

from src.cemcp.program_schema import ALLOWED_CALLS
from src.lab.safety_guard import FORBIDDEN_BUILTINS, FORBIDDEN_MODULES

# Builtins exposed to the replayed program. Restricted to the same call surface
# the AST interpreter supports (program_schema.ALLOWED_CALLS minus call_tool,
# which is injected separately as the controlled tool entrypoint).
SAFE_BUILTIN_NAMES = tuple(sorted(ALLOWED_CALLS - {"call_tool"}))


class PolicyError(Exception):
    pass


def validate_program(source: str) -> None:
    """Raise PolicyError if the program uses anything outside the AST language."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise PolicyError(f"syntax_error: {exc}") from exc

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            raise PolicyError("import is forbidden")
        if isinstance(node, ast.While):
            raise PolicyError("while loops are forbidden")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            raise PolicyError("function/class definitions are forbidden")
        if isinstance(node, ast.Lambda):
            raise PolicyError("lambda is forbidden")
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            raise PolicyError("import is forbidden")
        if isinstance(node, ast.JoinedStr):
            raise PolicyError("f-strings are forbidden")
        if isinstance(node, ast.AugAssign):
            raise PolicyError("augmented assignment is forbidden")
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            raise PolicyError("dunder attribute access forbidden")
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_MODULES:
            raise PolicyError(f"forbidden name: {node.id}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            fname = node.func.id
            if fname in FORBIDDEN_BUILTINS:
                raise PolicyError(f"forbidden call: {fname}")
            if fname not in ALLOWED_CALLS:
                raise PolicyError(f"call not allowlisted: {fname}")
        if isinstance(node, ast.Call) and not isinstance(node.func, ast.Name):
            raise PolicyError("only simple function calls allowed")


def restricted_builtins() -> dict:
    import builtins as _b

    allowed = {name: getattr(_b, name) for name in SAFE_BUILTIN_NAMES if hasattr(_b, name)}
    # Constants the AST interpreter recognizes.
    allowed.update({"True": True, "False": False, "None": None})
    return allowed
