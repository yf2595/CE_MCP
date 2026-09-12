"""Always-on host-safety layer (not an experimental defense)."""

from __future__ import annotations

FORBIDDEN_BUILTINS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "open",
        "input",
        "breakpoint",
    }
)

FORBIDDEN_MODULES = frozenset(
    {
        "os",
        "subprocess",
        "socket",
        "ctypes",
        "multiprocessing",
        "pathlib",
        "sys",
        "importlib",
        "builtins",
    }
)


class HostSafetyError(RuntimeError):
    pass


def assert_no_real_eval(payload: str) -> None:
    """Document that sim_eval never calls eval; raise if code path tries."""
    raise HostSafetyError("real eval is forbidden; use sim_eval simulation only")


def assert_no_subprocess() -> None:
    raise HostSafetyError("subprocess is forbidden in the lab")


def assert_no_network() -> None:
    raise HostSafetyError("network access is forbidden from MCP tools")


def check_program_ast_forbidden(names: set[str]) -> None:
    bad = names & (FORBIDDEN_BUILTINS | FORBIDDEN_MODULES)
    if bad:
        raise HostSafetyError(f"forbidden symbols in program: {sorted(bad)}")
