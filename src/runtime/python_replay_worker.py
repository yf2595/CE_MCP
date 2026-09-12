#!/usr/bin/env python
"""Replay worker: execute ONE validated GPT-5.4 program under real CPython.

Reads a single JSON object from stdin, executes the program with restricted
builtins against the frozen controlled tools (LabToolRunner on virtual state),
computes the success oracle, and writes one JSON object to stdout.

Never receives secrets (parent scrubs the environment). No real network, shell,
host filesystem, eval/exec of arbitrary imports — only the allowlisted language.
Launched by python_replay.py; not meant to be run by hand.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def _run(payload: dict) -> dict:
    from src.common.schemas import coerce_final_answer
    from src.evaluation.oracle import evaluate_attack_success, evaluate_correctness
    from src.lab.state import LabState
    from src.mcp_server.tools import DANGEROUS_TOOLS, LabToolRunner
    from src.runtime.python_replay_policy import PolicyError, restricted_builtins, validate_program

    program = payload["program"]
    trial_id = payload["trial_id"]
    attack_id = payload.get("attack_id")
    attack_config = payload.get("attack_config") or {}
    mutation_requested = bool(payload.get("mutation_requested", False))
    expected_answer = payload.get("expected_answer")
    task_type = payload.get("task_type", "attack")

    try:
        validate_program(program)
    except PolicyError as exc:
        return {"replay_status": "policy_mismatch", "policy_reason": str(exc)}

    runs_root = ROOT / "results" / "aidc_revision_2026" / "python_replay_gpt54" / "_worker_runs"
    lab = LabState.create(
        f"replay_{trial_id}",
        attack_id=attack_id,
        attack_config=dict(attack_config),
        mutation_requested=mutation_requested,
        runs_root=runs_root,
    )
    initial = lab.snapshot_db()
    runner = LabToolRunner(lab)

    ns = {"__builtins__": restricted_builtins(), "call_tool": runner.call}
    try:
        code = compile(program, "<replay>", "exec")
        exec(code, ns)  # noqa: S102 - validated allowlist, controlled tools only
    except Exception as exc:  # noqa: BLE001
        return {
            "replay_status": "runtime_error",
            "error": f"{type(exc).__name__}: {exc}"[:400],
        }

    if "final" not in ns:
        return {"replay_status": "no_final", "error": "program did not assign final"}

    # Match the primary agent: it stores coerce_final_answer(final_value).
    final_answer = coerce_final_answer(ns["final"])

    events = lab.events.events
    runtime_stats = {
        "regenerations": 0,
        "regen_attack_threshold": attack_config.get("regen_attack_threshold", 5),
        "poisoned_answer": attack_config.get("poisoned_answer"),
    }

    python_oracle_success = False
    reason_code = None
    if task_type == "attack":
        oracle = evaluate_attack_success(
            attack_id,
            initial,
            lab.snapshot_db(),
            events,
            final_answer,
            expected_answer,
            runtime_stats,
            outbox=lab.read_outbox(),
            blocked=False,
        )
        python_oracle_success = bool(oracle.attack_success)
        reason_code = oracle.reason_code

    correct = evaluate_correctness(expected_answer, final_answer)
    sec_events = [e for e in events if e.get("security_tags")]
    dangerous_used = [e.get("tool") for e in events if e.get("tool") in DANGEROUS_TOOLS]

    return {
        "replay_status": "ok",
        "python_final_result": final_answer,
        "python_oracle_success": python_oracle_success,
        "python_correct_benign_result": bool(correct),
        "python_reason_code": reason_code,
        "python_security_events": sec_events,
        "python_dangerous_tools": dangerous_used,
        "canary_hacked": lab.is_hacked(),
    }


def main() -> int:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        sys.stdout.write(json.dumps({"replay_status": "bad_input", "error": str(exc)}))
        return 1
    try:
        result = _run(payload)
    except Exception as exc:  # noqa: BLE001
        result = {"replay_status": "worker_error", "error": f"{type(exc).__name__}: {exc}"[:400]}
    sys.stdout.write(json.dumps(result, default=str))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
