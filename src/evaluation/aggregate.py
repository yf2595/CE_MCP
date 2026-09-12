"""Aggregate results with sanity checks."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import pandas as pd

from src.attacks.definitions import ATTACK_DEFINITIONS
from src.common.utils import RESULTS_DIR, ensure_dir, read_jsonl
from src.evaluation.metrics import asr, clean_success, defense_delta, filter_trials, mean_latency, overhead_vs_baseline, stcr


class AggregationError(RuntimeError):
    pass


def sanity_check(rows: list[dict[str, Any]], *, expected_min_attack_trials: int | None = None) -> None:
    ids = [r.get("trial_id") for r in rows]
    if len(ids) != len(set(ids)):
        raise AggregationError("duplicate trial IDs")
    for r in rows:
        if bool(r.get("attack_success")) != bool(r.get("canary_hacked")) and r.get("task_type") == "attack":
            raise AggregationError(f"canary inconsistent with oracle: {r.get('trial_id')}")
    models = {r.get("agent_model") for r in rows if r.get("agent_model")}
    # Allow only configured snapshots if present
    if expected_min_attack_trials is not None:
        attack_rows = [r for r in rows if r.get("task_type") == "attack"]
        if len(attack_rows) < expected_min_attack_trials:
            raise AggregationError(
                f"expected at least {expected_min_attack_trials} attack trials, found {len(attack_rows)}"
            )


def aggregate_all(
    trials_path: Path | None = None,
    *,
    confidence: float = 0.95,
    bootstrap_resamples: int = 10000,
    bootstrap_seed: int = 42,
) -> dict[str, Path]:
    path = trials_path or (RESULTS_DIR / "raw" / "trials.jsonl")
    rows = read_jsonl(path)
    if not rows:
        raise AggregationError("no trials to aggregate")
    sanity_check(rows)

    agg_dir = ensure_dir(RESULTS_DIR / "aggregate")
    outputs: dict[str, Path] = {}

    # security_by_attack
    attack_rows = []
    for attack_id, meta in ATTACK_DEFINITIONS.items():
        for arch in ("traditional_mcp", "cemcp"):
            for defense in ("C0", "C1", "C2"):
                subset = filter_trials(
                    rows, task_type="attack", attack_id=attack_id, architecture=arch, defense=defense
                )
                if not subset and arch == "traditional_mcp" and not meta.get("mcp_comparable"):
                    attack_rows.append(
                        {
                            "attack_id": attack_id,
                            "phase": meta["phase"],
                            "relation": meta["relation"],
                            "architecture": arch,
                            "defense": defense,
                            "asr": "N/A",
                            "asr_low": "N/A",
                            "asr_high": "N/A",
                            "stcr": "N/A",
                            "n": 0,
                        }
                    )
                    continue
                if not subset:
                    continue
                a = asr(subset, confidence)
                s = stcr(subset, confidence)
                attack_rows.append(
                    {
                        "attack_id": attack_id,
                        "phase": meta["phase"],
                        "relation": meta["relation"],
                        "architecture": arch,
                        "defense": defense,
                        "asr": a["asr"],
                        "asr_low": a["asr_low"],
                        "asr_high": a["asr_high"],
                        "stcr": s["stcr"],
                        "n": a["n"],
                    }
                )
    df_attack = pd.DataFrame(attack_rows)
    p1 = agg_dir / "security_by_attack.csv"
    df_attack.to_csv(p1, index=False)
    outputs["security_by_attack"] = p1

    # by phase
    phase_rows = []
    for phase in range(1, 6):
        aids = [a for a, m in ATTACK_DEFINITIONS.items() if m["phase"] == phase]
        for defense in ("C0", "C1", "C2"):
            subset = [
                r
                for r in filter_trials(rows, task_type="attack", architecture="cemcp", defense=defense)
                if r.get("attack_id") in aids
            ]
            if not subset:
                continue
            a = asr(subset, confidence)
            phase_rows.append({"phase": phase, "defense": defense, **a})
    p2 = agg_dir / "security_by_phase.csv"
    pd.DataFrame(phase_rows).to_csv(p2, index=False)
    outputs["security_by_phase"] = p2

    # defense summary (CE-MCP)
    def_rows = []
    c0 = filter_trials(rows, task_type="attack", architecture="cemcp", defense="C0")
    for defense in ("C0", "C1", "C2"):
        subset = filter_trials(rows, task_type="attack", architecture="cemcp", defense=defense)
        if not subset:
            continue
        a = asr(subset, confidence)
        s = stcr(subset, confidence)
        oh = overhead_vs_baseline(subset, c0 or subset)
        clean = filter_trials(rows, task_type="clean", architecture="cemcp", defense=defense)
        cs = clean_success(clean, confidence) if clean else {"clean_success": None, "n": 0}
        def_rows.append(
            {
                "defense": defense,
                "asr": a["asr"],
                "asr_low": a["asr_low"],
                "asr_high": a["asr_high"],
                "stcr": s["stcr"],
                "clean_success": cs.get("clean_success"),
                "latency_overhead": oh["latency_overhead"],
                "token_overhead": oh["token_overhead"],
                "mean_latency_s": oh["mean_latency_s"],
                "n_attack": a["n"],
                "n_clean": cs.get("n"),
            }
        )
    p3 = agg_dir / "defense_summary.csv"
    pd.DataFrame(def_rows).to_csv(p3, index=False)
    outputs["defense_summary"] = p3

    # clean utility
    clean_rows = []
    for arch in ("traditional_mcp", "cemcp"):
        for defense in ("C0", "C1", "C2"):
            subset = filter_trials(rows, task_type="clean", architecture=arch, defense=defense)
            if not subset:
                continue
            cs = clean_success(subset, confidence)
            clean_rows.append(
                {
                    "architecture": arch,
                    "defense": defense,
                    **cs,
                    "mean_latency_s": mean_latency(subset),
                }
            )
    p4 = agg_dir / "clean_utility.csv"
    pd.DataFrame(clean_rows).to_csv(p4, index=False)
    outputs["clean_utility"] = p4

    # model summary
    model_rows = []
    models = sorted({r["agent_model"] for r in rows if r.get("agent_model")})
    for model in models:
        c0m = filter_trials(rows, task_type="attack", architecture="cemcp", defense="C0", agent_model=model)
        c2m = filter_trials(rows, task_type="attack", architecture="cemcp", defense="C2", agent_model=model)
        clean_c2 = filter_trials(rows, task_type="clean", architecture="cemcp", defense="C2", agent_model=model)
        model_rows.append(
            {
                "model": model,
                "c0_asr": asr(c0m, confidence)["asr"] if c0m else None,
                "c2_asr": asr(c2m, confidence)["asr"] if c2m else None,
                "c2_stcr": stcr(c2m, confidence)["stcr"] if c2m else None,
                "clean_success": clean_success(clean_c2, confidence)["clean_success"] if clean_c2 else None,
            }
        )
    p5 = agg_dir / "model_summary.csv"
    pd.DataFrame(model_rows).to_csv(p5, index=False)
    outputs["model_summary"] = p5

    # paired deltas C2 - C0
    c0_all = filter_trials(rows, task_type="attack", architecture="cemcp", defense="C0")
    c2_all = filter_trials(rows, task_type="attack", architecture="cemcp", defense="C2")
    deltas = []
    if c0_all and c2_all:
        deltas.append(
            {
                "metric": "attack_success",
                **defense_delta(
                    c0_all, c2_all, metric="attack_success", resamples=bootstrap_resamples, seed=bootstrap_seed
                ),
            }
        )
        deltas.append(
            {
                "metric": "secure_correct",
                **defense_delta(
                    c0_all, c2_all, metric="secure_correct", resamples=bootstrap_resamples, seed=bootstrap_seed
                ),
            }
        )
    p6 = agg_dir / "paired_deltas.csv"
    pd.DataFrame(deltas).to_csv(p6, index=False)
    outputs["paired_deltas"] = p6

    # markdown mirrors
    for name, csv_path in list(outputs.items()):
        md_path = agg_dir / f"{name}.md"
        try:
            df = pd.read_csv(csv_path)
            if df.empty:
                md_path.write_text("(empty)\n", encoding="utf-8")
            else:
                try:
                    md_path.write_text(df.to_markdown(index=False), encoding="utf-8")
                except Exception:
                    md_path.write_text(df.to_string(index=False), encoding="utf-8")
        except Exception as exc:
            md_path.write_text(f"(unavailable: {exc})\n", encoding="utf-8")

    return outputs
