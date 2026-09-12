#!/usr/bin/env python
"""Run the full frozen suite for ONE model into results/aidc_revision_2026/<model>.

Writes v2.0 JSONL records with deterministic trial IDs and resumes without
duplicates. Legacy runner/data are never touched.

Trial IDs (plan 11.5):
  adversarial: {arch}__{config}__{model_key}__{attack_id}__seed{seed}__payload{payload}
  clean:       {arch}__{config}__{model_key}__clean__task{task_id}
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.agents.ce_mcp import CEMCPAgent
from src.agents.traditional_mcp import TraditionalMCPAgent
from src.attacks.clean_tasks import load_clean_tasks
from src.attacks.definitions import ATTACK_DEFINITIONS
from src.attacks.expansion import expand_attack_trials
from src.backends import accounting
from src.backends.registry import model_spec
from src.common.logging import setup_logging
from src.common.utils import ensure_dir, load_yaml, read_jsonl
from src.defenses.policy import DefensePolicy
from src.evaluation.oracle import apply_canary, evaluate_attack_success, evaluate_correctness
from src.evaluation.runner import load_experiment_config
from src.experiments.schema import TrialRecordV2, git_commit
from src.lab.state import LabState
from src.mcp_server.tools import LabToolRunner
from src.validation.frozen_manifest import load_manifest

ARCH_TAG = {"cemcp": "ce_mcp", "traditional_mcp": "trad_mcp"}
SMOKE_ATTACK_PER_PHASE = ["P1.1", "P2.1", "P3.2", "P4.1", "P5.5"]


def _append_atomic(path: Path, record: dict[str, Any]) -> None:
    ensure_dir(path.parent)
    line = json.dumps(record, default=str) + "\n"
    with path.open("a", encoding="utf-8") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())


def _security_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in events if e.get("security_tags")]


def _build_policy(defense: str, cfg: dict[str, Any]) -> DefensePolicy:
    host = cfg.get("host_safety") or {}
    runtime = cfg.get("runtime_defense") or {}
    policy = DefensePolicy.for_mode(
        defense,
        host_max_regen=int(host.get("max_ce_regenerations", 8)),
        runtime_max_regen=int(runtime.get("max_regenerations", 2)),
    )
    policy.max_simulated_resource_units = int(runtime.get("max_simulated_resource_units", 20))
    return policy


def _run_one(
    *,
    task_type: str,
    trial_id: str,
    architecture: str,
    defense: str,
    model_key: str,
    spec: dict[str, Any],
    provider: str,
    requested_model: str,
    judge_model_key: str | None,
    cfg: dict[str, Any],
    run_id: str,
    manifest_sha: str | None,
    runs_root: Path,
    policy: DefensePolicy | None = None,
    defense_label: str | None = None,
) -> TrialRecordV2:
    host = cfg.get("host_safety") or {}
    if policy is None:
        policy = _build_policy(defense, cfg)
    defense_config = defense_label or defense
    attack_id = spec.get("attack_id")

    lab = LabState.create(
        trial_id,
        attack_id=attack_id,
        attack_config=dict(spec.get("attack_config") or {}),
        mutation_requested=bool(spec.get("mutation_requested", False)),
        runs_root=runs_root,
    )
    initial = lab.snapshot_db()
    runner = LabToolRunner(lab, runtime_policy=policy.runtime_policy_dict())
    judge_model = judge_model_key if (policy.pre_gate or policy.post_gate) else None

    with accounting.collect() as turns:
        if architecture == "traditional_mcp":
            agent = TraditionalMCPAgent(
                runner,
                model=model_key,
                max_turns=int(host.get("max_agent_turns", 12)),
                temperature=float(cfg.get("temperature", 0)),
            )
        else:
            agent = CEMCPAgent(
                runner,
                model=model_key,
                judge_model=judge_model,
                policy=policy,
                temperature=float(cfg.get("temperature", 0)),
                max_program_steps=int(host.get("max_program_steps", 100)),
            )
        result = agent.run(spec["user_request"])
    stats = accounting.summarize(turns)

    correct = evaluate_correctness(spec["expected_answer"], result.final_answer) and not result.blocked

    attack_success = False
    canary = False
    oracle_details: dict[str, Any] = {}
    if task_type == "attack":
        runtime_stats = {
            "regenerations": result.regenerations,
            "regen_attack_threshold": (spec.get("attack_config") or {}).get("regen_attack_threshold", 5),
            "poisoned_answer": (spec.get("attack_config") or {}).get("poisoned_answer"),
        }
        oracle = evaluate_attack_success(
            attack_id,
            initial,
            lab.snapshot_db(),
            result.events or lab.events.events,
            result.final_answer,
            spec["expected_answer"],
            runtime_stats,
            outbox=lab.read_outbox(),
            blocked=result.blocked,
        )
        apply_canary(lab, oracle)
        attack_success = oracle.attack_success
        canary = lab.is_hacked()
        oracle_details = {"reason_code": oracle.reason_code, **(oracle.details or {})}
        if attack_success != canary:
            raise RuntimeError(f"canary/oracle mismatch for {trial_id}")

    secure_task_completion = (not attack_success) and correct

    events = result.events or lab.events.events
    spec_top_p = model_spec(model_key).get("top_p")
    spec_seed = model_spec(model_key).get("seed")

    record = TrialRecordV2(
        run_id=run_id,
        trial_id=trial_id,
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        git_commit=git_commit(),
        suite_manifest_sha256=manifest_sha,
        model_key=model_key,
        provider=provider,
        requested_model=requested_model,
        returned_model=stats.returned_model,
        reasoning_mode=stats.reasoning_mode,
        reasoning_control_source=stats.reasoning_control_source,
        temperature=float(cfg.get("temperature", 0)) if provider != "openai_responses" else None,
        top_p=spec_top_p,
        seed=spec_seed,
        architecture=architecture,
        defense_config=defense_config,
        attack_id=attack_id,
        phase=spec.get("phase"),
        task_seed=spec.get("task_seed"),
        payload_variant=spec.get("payload_variant"),
        task_type=task_type,
        user_request=spec["user_request"],
        expected_answer=spec["expected_answer"],
        attack_success=attack_success,
        secure_task_completion=secure_task_completion,
        correct_benign_result=correct,
        canary_hacked=canary,
        oracle_details=oracle_details,
        security_events=_security_events(events),
        agent_regeneration_budget=policy.max_regenerations,
        agent_regeneration_count=result.regenerations,
        transport_retry_count=stats.transport_retry_count,
        tool_retry_count=0,
        model_call_count=result.model_calls or stats.model_call_count,
        tool_call_count=result.tool_calls,
        latency_seconds=result.latency_s,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        reasoning_tokens=stats.reasoning_tokens,
        cached_input_tokens=stats.cached_input_tokens,
        generated_program=result.generated_program,
        final_result=result.final_answer,
        termination_reason=result.status or ("blocked" if result.blocked else "completed"),
        trial_status="valid",
        request_ids=stats.request_ids or [],
        errors=[result.reason_code] if result.reason_code else [],
    )
    return record


def _adversarial_specs(experiment: dict[str, Any]) -> list[dict[str, Any]]:
    attack_ids = list(ATTACK_DEFINITIONS)
    return expand_attack_trials(
        attack_ids,
        n_seeds=int(experiment.get("task_seeds", 3)),
        n_variants=int(experiment.get("payload_variants", 3)),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-key", required=True)
    parser.add_argument("--experiment", default="configs/experiments/frozen_full_suite.yaml")
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--base-url", default=None, help="Local vLLM endpoint for vllm_chat models.")
    parser.add_argument("--smoke", action="store_true", help="One trial per phase + 2 clean, C0 only.")
    parser.add_argument("--limit", type=int, default=None, help="Cap number of trials (debug).")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help=(
            "Number of trials to run in parallel against the model endpoint. "
            "Default 1 (sequential, unchanged). Higher values (e.g. 6-8) batch "
            "requests on a local vLLM server for large speedups WITHOUT changing "
            "per-trial params/seed. Each trial is independent; only wall-clock "
            "improves."
        ),
    )
    args = parser.parse_args()

    log = setup_logging()
    if args.base_url:
        os.environ["WAITI_VLLM_ENDPOINT"] = args.base_url

    experiment = load_yaml(ROOT / args.experiment)
    cfg = load_experiment_config()
    spec_model = model_spec(args.model_key)
    provider = spec_model["provider"]
    requested_model = spec_model.get("model") or spec_model.get("served_model_name")
    manifest = load_manifest()
    manifest_sha = manifest.get("suite_manifest_sha256") if manifest else None

    out_root = Path(args.output_root)
    ensure_dir(out_root)
    results_path = out_root / "trials.jsonl"
    runs_root = out_root / "runs"
    run_id = f"{experiment.get('name', 'suite')}__{args.model_key}"
    judge_model_key = experiment.get("judge_model_key", "gpt54_low")

    # Resume logic: keep successful records, but DROP prior infrastructure
    # failures (e.g. a transient missing OPENAI_API_KEY for the C2 judge) so they
    # are retried on the next run. This also prevents duplicate trial_ids when a
    # previously-failed trial succeeds on retry.
    prior_records = read_jsonl(results_path) if results_path.exists() else []
    good_records = [r for r in prior_records if r.get("trial_status") != "infrastructure_failure"]
    n_dropped = len(prior_records) - len(good_records)
    if n_dropped:
        tmp_path = results_path.with_suffix(".jsonl.tmp")
        with open(tmp_path, "w", encoding="utf-8") as fh:
            for r in good_records:
                fh.write(json.dumps(r) + "\n")
        os.replace(tmp_path, results_path)
        log.info("dropped %d prior infrastructure_failure record(s) to retry", n_dropped)
    done = {r["trial_id"] for r in good_records if "trial_id" in r}
    log.info("resume: %d trials already recorded", len(done))

    # Build the work list.
    work: list[dict[str, Any]] = []
    adversarial = _adversarial_specs(experiment)
    if args.smoke:
        adversarial = [
            s for s in adversarial
            if s["attack_id"] in SMOKE_ATTACK_PER_PHASE
            and s.get("task_seed") == 0
            and s.get("payload_variant") == 1
        ]
        # one per phase: keep first occurrence per attack_id
        seen: set[str] = set()
        dedup = []
        for s in adversarial:
            if s["attack_id"] in seen:
                continue
            seen.add(s["attack_id"])
            dedup.append(s)
        adversarial = dedup

    ce_defenses = ["C0"] if args.smoke else list(experiment.get("ce_defenses", ["C0", "C1", "C2"]))
    architectures = ["cemcp"] if args.smoke else list(experiment.get("architectures", ["cemcp"]))

    for spec in adversarial:
        for arch in architectures:
            if arch == "traditional_mcp":
                if not ATTACK_DEFINITIONS[spec["attack_id"]].get("mcp_comparable"):
                    continue
                defenses = ["C0"]
            else:
                defenses = ce_defenses
            for defense in defenses:
                tid = (
                    f"{ARCH_TAG[arch]}__{defense}__{args.model_key}__{spec['attack_id']}"
                    f"__seed{spec['task_seed']}__payload{spec['payload_variant']}"
                )
                work.append({"task_type": "attack", "trial_id": tid, "arch": arch, "defense": defense, "spec": spec})

    # Clean tasks.
    if experiment.get("include_clean", True):
        clean_tasks = load_clean_tasks()
        clean_configs = experiment.get("clean_configs") or [["cemcp", "C0"]]
        if args.smoke:
            clean_tasks = clean_tasks[:2]
            clean_configs = [["cemcp", "C0"]]
        for task in clean_tasks:
            clean_spec = {
                "attack_id": None,
                "attack_config": {},
                "mutation_requested": task.get("mutation_requested", False),
                "phase": None,
                "task_seed": None,
                "payload_variant": None,
                "user_request": task["user_request"],
                "expected_answer": task["expected_answer"],
            }
            for arch, defense in clean_configs:
                tid = f"{ARCH_TAG[arch]}__{defense}__{args.model_key}__clean__task{task['task_id']}"
                work.append(
                    {"task_type": "clean", "trial_id": tid, "arch": arch, "defense": defense, "spec": clean_spec}
                )

    todo = [w for w in work if w["trial_id"] not in done]
    if args.limit:
        todo = todo[: args.limit]
    log.info("total work=%d, remaining=%d", len(work), len(todo))

    n_total = len(todo)
    counters = {"ok": 0, "fail": 0, "done": 0}
    io_lock = threading.Lock()

    def _process(w: dict[str, Any]) -> None:
        # Runs in a worker thread when --concurrency > 1. Each trial is fully
        # independent (own LabState/runner/output dir); accounting uses per-thread
        # context vars, so parallelism does not mix trials. Only the shared log
        # file and counters are guarded by io_lock.
        try:
            record = _run_one(
                task_type=w["task_type"],
                trial_id=w["trial_id"],
                architecture=w["arch"],
                defense=w["defense"],
                model_key=args.model_key,
                spec=w["spec"],
                provider=provider,
                requested_model=requested_model,
                judge_model_key=judge_model_key,
                cfg=cfg,
                run_id=run_id,
                manifest_sha=manifest_sha,
                runs_root=runs_root,
            )
            payload = record.model_dump()
            status_ok = True
        except Exception as exc:  # noqa: BLE001 - record infra failure, never drop
            log.exception("trial failed: %s", w["trial_id"])
            payload = {
                "schema_version": "2.0",
                "run_id": run_id,
                "trial_id": w["trial_id"],
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "model_key": args.model_key,
                "provider": provider,
                "architecture": w["arch"],
                "defense_config": w["defense"],
                "attack_id": w["spec"].get("attack_id"),
                "task_type": w["task_type"],
                "trial_status": "infrastructure_failure",
                "errors": [str(exc)[:500]],
            }
            status_ok = False
        with io_lock:
            _append_atomic(results_path, payload)
            counters["done"] += 1
            counters["ok" if status_ok else "fail"] += 1
            log.info("[%d/%d] %s%s", counters["done"], n_total, w["trial_id"],
                     "" if status_ok else "  (FAILED)")

    concurrency = max(1, int(args.concurrency))
    if concurrency == 1:
        for w in todo:
            _process(w)
    else:
        log.info("running with concurrency=%d", concurrency)
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            list(pool.map(_process, todo))

    n_ok = counters["ok"]
    n_fail = counters["fail"]
    print("done")
    print(f"results: {results_path}")
    print(f"valid_appended={n_ok} infrastructure_failures={n_fail} skipped_existing={len(work) - len(todo)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
