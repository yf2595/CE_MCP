#!/usr/bin/env python
"""P5.5 regeneration-budget sensitivity sweep (plan section 13). GPT-5.4 only.

Holds everything constant (task seeds, payloads, tools, prompts, C0 host-safe
substrate, oracle, model, reasoning effort, transport policy, output limit) and
varies ONLY the agent regeneration budget in {1,2,4,8}. Runs the malicious P5.5
cases and matched benign versions (payload disabled) of the same tasks.

Budget names: P55-B1, P55-B2, P55-B4, P55-B8 (never call budget 2 "C1").
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.attacks.expansion import expand_attack_trials
from src.common.logging import setup_logging
from src.common.utils import ensure_dir, load_yaml, read_jsonl
from src.defenses.policy import DefensePolicy
from src.evaluation.runner import load_experiment_config
from src.experiments.run_suite import _append_atomic, _run_one
from src.validation.frozen_manifest import load_manifest


def _c0_policy_with_budget(cfg: dict[str, Any], budget: int) -> DefensePolicy:
    host = cfg.get("host_safety") or {}
    runtime = cfg.get("runtime_defense") or {}
    policy = DefensePolicy.for_mode(
        "C0",
        host_max_regen=int(host.get("max_ce_regenerations", 8)),
        runtime_max_regen=int(runtime.get("max_regenerations", 2)),
    )
    policy.max_simulated_resource_units = int(runtime.get("max_simulated_resource_units", 20))
    # The only knob that changes across conditions.
    policy.max_regenerations = int(budget)
    return policy


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--experiment", default="configs/experiments/p55_budget_gpt54.yaml")
    parser.add_argument("--output-root", default="results/aidc_revision_2026/p55_budget_gpt54")
    args = parser.parse_args()

    log = setup_logging()
    exp = load_yaml(ROOT / args.experiment)
    cfg = load_experiment_config()

    model_key = exp.get("model_key", "gpt54_low")
    if model_key != "gpt54_low":
        raise SystemExit("P5.5 budget sweep is GPT-5.4 only (plan 13.1).")
    attack_id = exp.get("attack_id", "P5.5")
    budgets = list(exp.get("budgets", [1, 2, 4, 8]))
    n_seeds = int(exp.get("task_seeds", 3))
    n_variants = int(exp.get("payload_variants", 3))

    from src.backends.registry import model_spec

    spec_model = model_spec(model_key)
    provider = spec_model["provider"]
    requested_model = spec_model.get("model")
    manifest = load_manifest()
    manifest_sha = manifest.get("suite_manifest_sha256") if manifest else None

    out_root = ensure_dir(Path(args.output_root))
    results_path = out_root / "trials.jsonl"
    runs_root = out_root / "runs"
    run_id = exp.get("name", "p55_budget_gpt54")
    done = {r["trial_id"] for r in read_jsonl(results_path) if "trial_id" in r}

    p55_specs = expand_attack_trials([attack_id], n_seeds=n_seeds, n_variants=n_variants)

    work: list[dict[str, Any]] = []
    for budget in budgets:
        label = f"P55-B{budget}"
        for spec in p55_specs:
            # Malicious.
            mal_id = f"ce_mcp__{label}__{model_key}__{attack_id}__seed{spec['task_seed']}__payload{spec['payload_variant']}"
            work.append({"trial_id": mal_id, "budget": budget, "label": label, "spec": spec, "task_type": "attack"})
            # Matched benign: same task, payload disabled (attack_id=None).
            if exp.get("include_benign", True):
                benign_spec = dict(spec)
                benign_spec["attack_id"] = None
                benign_spec["attack_config"] = {}
                ben_id = f"ce_mcp__{label}__{model_key}__benign__seed{spec['task_seed']}__payload{spec['payload_variant']}"
                work.append({"trial_id": ben_id, "budget": budget, "label": label, "spec": benign_spec, "task_type": "clean"})

    todo = [w for w in work if w["trial_id"] not in done]
    log.info("p55 sweep: total=%d remaining=%d", len(work), len(todo))

    n_ok = 0
    for i, w in enumerate(todo, 1):
        log.info("[%d/%d] %s", i, len(todo), w["trial_id"])
        policy = _c0_policy_with_budget(cfg, w["budget"])
        try:
            record = _run_one(
                task_type=w["task_type"],
                trial_id=w["trial_id"],
                architecture="cemcp",
                defense="C0",
                model_key=model_key,
                spec=w["spec"],
                provider=provider,
                requested_model=requested_model,
                judge_model_key=None,  # C0 host-safe substrate: no gates
                cfg=cfg,
                run_id=run_id,
                manifest_sha=manifest_sha,
                runs_root=runs_root,
                policy=policy,
                defense_label=w["label"],
            )
            _append_atomic(results_path, record.model_dump())
            n_ok += 1
        except Exception as exc:  # noqa: BLE001
            log.exception("p55 trial failed: %s", w["trial_id"])
            _append_atomic(
                results_path,
                {
                    "schema_version": "2.0",
                    "run_id": run_id,
                    "trial_id": w["trial_id"],
                    "model_key": model_key,
                    "defense_config": w["label"],
                    "attack_id": w["spec"].get("attack_id"),
                    "task_type": w["task_type"],
                    "trial_status": "infrastructure_failure",
                    "errors": [str(exc)[:500]],
                },
            )

    print("done")
    print(f"results: {results_path}")
    print(f"valid_appended={n_ok} skipped_existing={len(work) - len(todo)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
