#!/usr/bin/env python
"""Run the controlled CPython replay over the fixed GPT-5.4 subset (plan 12).

Reuses the exact GPT-5.4 C0 program strings (never regenerates), replays each
under restricted CPython, and compares against the AST-executor verdict already
recorded. Writes per-record agreement metrics.

The critical check: python_only_attack_success_count == 0.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.attacks.clean_tasks import load_clean_tasks
from src.attacks.definitions import ATTACK_DEFINITIONS
from src.attacks.expansion import expand_attack_trials
from src.common.logging import setup_logging
from src.common.utils import ensure_dir, load_yaml, read_jsonl
from src.runtime.python_replay import replay_program


def _adv_lookup() -> dict[tuple, dict[str, Any]]:
    specs = expand_attack_trials(list(ATTACK_DEFINITIONS), n_seeds=10, n_variants=3)
    return {(s["attack_id"], s["task_seed"], s["payload_variant"]): s for s in specs}


def _clean_lookup() -> dict[str, dict[str, Any]]:
    return {t["task_id"]: t for t in load_clean_tasks()}


def _parse_clean_task_id(trial_id: str) -> str | None:
    # ..._clean__task{task_id}
    marker = "__clean__task"
    if marker in trial_id:
        return trial_id.split(marker, 1)[1]
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--experiment", default="configs/experiments/python_replay_gpt54.yaml")
    parser.add_argument("--output-root", default="results/aidc_revision_2026/python_replay_gpt54")
    args = parser.parse_args()

    log = setup_logging()
    exp = load_yaml(ROOT / args.experiment)
    src_path = ROOT / exp["source_results"]
    if not src_path.exists():
        print(f"source results not found: {src_path}")
        return 1

    rows = read_jsonl(src_path)
    replay_attacks = set(exp["replay_attacks"])
    timeout_s = int(exp.get("timeout_seconds", 10))

    adv_lookup = _adv_lookup()
    clean_lookup = _clean_lookup()

    # Select adversarial C0 CE-MCP programs.
    adv_records = [
        r for r in rows
        if r.get("task_type") == "attack"
        and r.get("architecture") == "cemcp"
        and r.get("defense_config") == "C0"
        and r.get("attack_id") in replay_attacks
        and r.get("generated_program")
    ]
    # Select clean C0 CE-MCP programs.
    clean_records = [
        r for r in rows
        if r.get("task_type") == "clean"
        and r.get("architecture") == "cemcp"
        and r.get("defense_config") == "C0"
        and r.get("generated_program")
    ][: int(exp.get("clean_count", 20))]

    out_root = ensure_dir(Path(args.output_root))
    out_path = out_root / "replay.jsonl"
    if out_path.exists():
        out_path.unlink()

    log.info("adversarial replays=%d clean replays=%d", len(adv_records), len(clean_records))

    records_out: list[dict[str, Any]] = []

    def _do(r: dict[str, Any], task_type: str) -> None:
        program = r["generated_program"]
        if task_type == "attack":
            spec = adv_lookup.get((r["attack_id"], r.get("task_seed"), r.get("payload_variant")))
            attack_config = (spec or {}).get("attack_config", {})
            mutation = bool((spec or {}).get("mutation_requested", False))
            expected = r.get("expected_answer") if spec is None else spec["expected_answer"]
        else:
            task_id = _parse_clean_task_id(r["trial_id"])
            task = clean_lookup.get(task_id or "", {})
            attack_config = {}
            mutation = bool(task.get("mutation_requested", False))
            expected = r.get("expected_answer")

        payload = {
            "program": program,
            "trial_id": r["trial_id"],
            "attack_id": r.get("attack_id"),
            "attack_config": attack_config,
            "mutation_requested": mutation,
            "expected_answer": expected,
            "task_type": task_type,
        }
        res = replay_program(payload, timeout_s=timeout_s)

        ast_success = bool(r.get("attack_success")) if task_type == "attack" else False
        py_success = bool(res.get("python_oracle_success", False))
        ast_final = r.get("final_result")
        py_final = res.get("python_final_result")
        status = res.get("replay_status")

        record = {
            "trial_id": r["trial_id"],
            "attack_id": r.get("attack_id"),
            "task_type": task_type,
            "replay_status": status,
            "ast_oracle_success": ast_success,
            "python_oracle_success": py_success,
            "ast_final_result": ast_final,
            "python_final_result": py_final,
            "ast_security_events": r.get("security_events", []),
            "python_security_events": res.get("python_security_events", []),
            "verdict_agreement": (ast_success == py_success) if task_type == "attack" else None,
            "result_agreement": _equalish(ast_final, py_final),
            "python_only_success": (py_success and not ast_success) if task_type == "attack" else False,
            "ast_only_success": (ast_success and not py_success) if task_type == "attack" else False,
            "policy_mismatch": status == "policy_mismatch",
            "timeout": bool(res.get("timeout", False)),
            "exit_code": res.get("exit_code"),
            "latency_seconds": res.get("latency_seconds"),
            "error": res.get("error"),
        }
        records_out.append(record)

    for i, r in enumerate(adv_records, 1):
        log.info("[adv %d/%d] %s", i, len(adv_records), r["trial_id"])
        _do(r, "attack")
    for i, r in enumerate(clean_records, 1):
        log.info("[clean %d/%d] %s", i, len(clean_records), r["trial_id"])
        _do(r, "clean")

    from src.common.utils import append_jsonl

    for rec in records_out:
        append_jsonl(out_path, rec)

    # Summary.
    n = len(records_out)
    python_only = sum(1 for r in records_out if r["python_only_success"])
    ast_only = sum(1 for r in records_out if r["ast_only_success"])
    attacks = [r for r in records_out if r["task_type"] == "attack"]
    verdict_agree = sum(1 for r in attacks if r["verdict_agreement"])
    result_agree = sum(1 for r in records_out if r["result_agreement"])
    policy_mismatch = sum(1 for r in records_out if r["policy_mismatch"])
    timeouts = sum(1 for r in records_out if r["timeout"])

    print("\n============ CPython replay summary ============")
    print(f"  total replays:            {n}")
    print(f"  adversarial / clean:      {len(attacks)} / {n - len(attacks)}")
    print(f"  verdict agreement:        {verdict_agree}/{len(attacks)}")
    print(f"  result agreement:         {result_agree}/{n}")
    print(f"  PYTHON-ONLY successes:     {python_only}   (must be 0)")
    print(f"  AST-only successes:        {ast_only}")
    print(f"  policy_mismatch:          {policy_mismatch}")
    print(f"  timeouts:                 {timeouts}")
    print(f"  written: {out_path}")
    print("================================================")
    if python_only:
        print("WARNING: python-only attack successes detected; review each before paper use.")
    return 0


def _equalish(a: Any, b: Any) -> bool:
    if a == b:
        return True
    return str(a).strip() == str(b).strip()


if __name__ == "__main__":
    raise SystemExit(main())
