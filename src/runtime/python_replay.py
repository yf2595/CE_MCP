"""Parent orchestrator for the controlled CPython replay.

Launches the worker in a scrubbed subprocess, feeds one program via stdin,
enforces a wall-clock timeout, and kills the whole process tree on timeout.
Cross-platform: POSIX resource limits are applied when available; on Windows the
timeout + psutil process-tree termination provide the bound.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]

# Env vars that must never reach the child.
_SECRET_KEYS = ("OPENAI_API_KEY", "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "OPENAI_BASE_URL")

DEFAULT_TIMEOUT_S = 10
CPU_TIME_LIMIT_S = 5
ADDRESS_SPACE_LIMIT = 2 * 1024 * 1024 * 1024  # 2 GB


_SECRET_SUBSTRINGS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL")


def _scrubbed_env() -> dict[str, str]:
    """Copy the environment (so Python can still import its packages) but remove
    every credential-like variable. The child must never receive OPENAI_API_KEY,
    HF tokens, etc. — but it DOES need the interpreter's normal environment.
    """
    env = dict(os.environ)
    for k in _SECRET_KEYS:
        env.pop(k, None)
    for k in list(env):
        upper = k.upper()
        if any(s in upper for s in _SECRET_SUBSTRINGS):
            env.pop(k, None)
    # Keep the child pointed at the repo for `-m src.runtime...` imports.
    env["PYTHONPATH"] = str(ROOT)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"
    return env


def _posix_preexec() -> Any:
    if os.name != "posix":
        return None

    def _limit() -> None:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (CPU_TIME_LIMIT_S, CPU_TIME_LIMIT_S))
        try:
            resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_LIMIT, ADDRESS_SPACE_LIMIT))
        except (ValueError, OSError):
            pass
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
        except (ValueError, OSError):
            pass

    return _limit


def _kill_tree(proc: subprocess.Popen) -> None:
    try:
        import psutil

        parent = psutil.Process(proc.pid)
        for child in parent.children(recursive=True):
            child.kill()
        parent.kill()
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


def replay_program(payload: dict[str, Any], *, timeout_s: int = DEFAULT_TIMEOUT_S) -> dict[str, Any]:
    """Run one program in the worker. Returns the worker JSON plus timing."""
    cmd = [sys.executable, "-m", "src.runtime.python_replay_worker"]
    preexec = _posix_preexec()
    kwargs: dict[str, Any] = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "cwd": str(ROOT),
        "env": _scrubbed_env(),
        "text": True,
    }
    if preexec is not None:
        kwargs["preexec_fn"] = preexec

    t0 = time.perf_counter()
    proc = subprocess.Popen(cmd, **kwargs)
    try:
        out, err = proc.communicate(input=json.dumps(payload), timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        return {
            "replay_status": "timeout",
            "timeout": True,
            "exit_code": None,
            "latency_seconds": round(time.perf_counter() - t0, 4),
        }
    latency = round(time.perf_counter() - t0, 4)

    try:
        result = json.loads(out) if out.strip() else {"replay_status": "empty_output"}
    except json.JSONDecodeError:
        result = {"replay_status": "unparseable_output", "raw_stdout": out[:500]}

    result.setdefault("timeout", False)
    result["exit_code"] = proc.returncode
    result["latency_seconds"] = latency
    if err.strip():
        result["worker_stderr"] = err[:500]
    return result
