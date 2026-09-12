#!/usr/bin/env python
"""Aggregate the AIDC revision results into paper-ready CSVs, LaTeX, and text.

Reads results/aidc_revision_2026/<model_key>/trials.jsonl for the paper 4-model
set (+ retained gpt41 reported separately), the CPython replay agreement, and the
P5.5 budget sweep. Produces everything under results/aidc_revision_2026/summary/.

Statistics: Wilson 95% CIs; McNemar exact test for architecture comparison.
Pooled ASR is labeled descriptive (never the headline).
"""

from __future__ import annotations

import argparse
import statistics
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402

from src.attacks.definitions import ATTACK_DEFINITIONS  # noqa: E402
from src.common.utils import ensure_dir, read_jsonl  # noqa: E402
from src.evaluation.ci import wilson_ci  # noqa: E402

PAPER_MODELS = ["gpt54_low", "gpt_oss_20b", "qwen3_14b", "llama31_8b"]
SECONDARY_MODELS = ["gpt41"]
MCP_COMPARABLE = [aid for aid, d in ATTACK_DEFINITIONS.items() if d.get("mcp_comparable")]

EXPECTED_CE_ADVERSARIAL = 16 * 3 * 3 * 3  # 432 per model
EXPECTED_TRAD_ADVERSARIAL = len(MCP_COMPARABLE) * 3 * 3  # 54 per model
EXPECTED_CLEAN = 40 * 4  # 160 per model


def _load_model(results_root: Path, model_key: str) -> list[dict[str, Any]]:
    path = results_root / model_key / "trials.jsonl"
    return read_jsonl(path)


def _valid(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in rows if r.get("trial_status", "valid") == "valid"]


def _fmt_ci(succ: int, n: int) -> str:
    p, lo, hi = wilson_ci(succ, n)
    return f"{100 * p:.1f}% [{100 * lo:.1f},{100 * hi:.1f}]"


def per_attack_per_model(all_rows: dict[str, list[dict]], out: Path) -> None:
    recs = []
    for model_key, rows in all_rows.items():
        rows = [r for r in _valid(rows) if r.get("task_type") == "attack"]
        df = pd.DataFrame(rows)
        if df.empty:
            continue
        for (attack_id, arch, defense), g in df.groupby(["attack_id", "architecture", "defense_config"]):
            n = len(g)
            succ = int(g["attack_success"].sum())
            stcr = float(g["secure_task_completion"].mean()) if n else 0.0
            p, lo, hi = wilson_ci(succ, n)
            recs.append(
                {
                    "model_key": model_key,
                    "attack_id": attack_id,
                    "phase": int(g["phase"].iloc[0]) if g["phase"].notna().any() else None,
                    "architecture": arch,
                    "defense_config": defense,
                    "n": n,
                    "successes": succ,
                    "asr": round(p, 4),
                    "asr_ci_low": round(lo, 4),
                    "asr_ci_high": round(hi, 4),
                    "asr_str": _fmt_ci(succ, n),
                    "stcr": round(stcr, 4),
                    "mean_latency_s": round(float(g["latency_seconds"].mean()), 3),
                    "mean_input_tokens": round(float(g["input_tokens"].mean()), 1),
                    "mean_output_tokens": round(float(g["output_tokens"].mean()), 1),
                    "mean_reasoning_tokens": round(float(g.get("reasoning_tokens", pd.Series([0])).mean()), 1),
                }
            )
    pd.DataFrame(recs).to_csv(out, index=False)


def defense_ladder(all_rows: dict[str, list[dict]], out: Path) -> None:
    recs = []
    macro: dict[tuple, list[float]] = {}
    for model_key, rows in all_rows.items():
        rows = [r for r in _valid(rows) if r.get("task_type") == "attack" and r.get("architecture") == "cemcp"]
        df = pd.DataFrame(rows)
        if df.empty:
            continue
        for (attack_id, defense), g in df.groupby(["attack_id", "defense_config"]):
            n = len(g)
            succ = int(g["attack_success"].sum())
            p, lo, hi = wilson_ci(succ, n)
            recs.append(
                {
                    "model_key": model_key,
                    "attack_id": attack_id,
                    "defense_config": defense,
                    "n": n,
                    "successes": succ,
                    "asr": round(p, 4),
                    "asr_str": _fmt_ci(succ, n),
                    "stcr": round(float(g["secure_task_completion"].mean()), 4),
                }
            )
            macro.setdefault((model_key, defense), []).append(p)
    # Macro-average across the 16 scenarios, per model + defense.
    for (model_key, defense), vals in macro.items():
        recs.append(
            {
                "model_key": model_key,
                "attack_id": "MACRO_AVG_16",
                "defense_config": defense,
                "n": len(vals),
                "successes": None,
                "asr": round(sum(vals) / len(vals), 4),
                "asr_str": f"{100 * sum(vals) / len(vals):.1f}% (macro; not deployment prevalence)",
                "stcr": None,
            }
        )
    # Four-model macro-average per defense (paper set only).
    paper = {k: v for k, v in macro.items() if k[0] in PAPER_MODELS}
    by_def: dict[str, list[float]] = {}
    for (model_key, defense), vals in paper.items():
        by_def.setdefault(defense, []).append(sum(vals) / len(vals))
    for defense, vals in by_def.items():
        recs.append(
            {
                "model_key": "FOUR_MODEL_MACRO",
                "attack_id": "MACRO_AVG_16",
                "defense_config": defense,
                "n": len(vals),
                "successes": None,
                "asr": round(sum(vals) / len(vals), 4),
                "asr_str": f"{100 * sum(vals) / len(vals):.1f}% (4-model macro)",
                "stcr": None,
            }
        )
    pd.DataFrame(recs).to_csv(out, index=False)


def architecture_comparison(all_rows: dict[str, list[dict]], out: Path) -> None:
    """Traditional-MCP C0 vs CE-MCP C0 on the 6 comparable attacks, with McNemar."""
    recs = []
    combined_trad = {"succ": 0, "n": 0}
    combined_ce = {"succ": 0, "n": 0}
    for model_key, rows in all_rows.items():
        if model_key not in PAPER_MODELS:
            continue
        rows = [r for r in _valid(rows) if r.get("task_type") == "attack" and r.get("defense_config") == "C0"]
        df = pd.DataFrame(rows)
        if df.empty:
            continue
        for attack_id in MCP_COMPARABLE:
            trad = df[(df["attack_id"] == attack_id) & (df["architecture"] == "traditional_mcp")]
            ce = df[(df["attack_id"] == attack_id) & (df["architecture"] == "cemcp")]
            if trad.empty and ce.empty:
                continue
            # McNemar on matched (seed,variant).
            b, c = _mcnemar_bc(trad, ce)
            pval = _mcnemar_exact(b, c)
            recs.append(
                {
                    "model_key": model_key,
                    "attack_id": attack_id,
                    "trad_n": len(trad),
                    "trad_asr": round(float(trad["attack_success"].mean()) if len(trad) else 0.0, 4),
                    "ce_n": len(ce),
                    "ce_asr": round(float(ce["attack_success"].mean()) if len(ce) else 0.0, 4),
                    "delta_ce_minus_trad": round(
                        (float(ce["attack_success"].mean()) if len(ce) else 0.0)
                        - (float(trad["attack_success"].mean()) if len(trad) else 0.0),
                        4,
                    ),
                    "mcnemar_b_trad_only": b,
                    "mcnemar_c_ce_only": c,
                    "mcnemar_p_exact": round(pval, 4),
                }
            )
            combined_trad["succ"] += int(trad["attack_success"].sum())
            combined_trad["n"] += len(trad)
            combined_ce["succ"] += int(ce["attack_success"].sum())
            combined_ce["n"] += len(ce)
    # Pooled DESCRIPTIVE summary (never the headline).
    recs.append(
        {
            "model_key": "POOLED_DESCRIPTIVE",
            "attack_id": "6_COMPARABLE",
            "trad_n": combined_trad["n"],
            "trad_asr": round(combined_trad["succ"] / combined_trad["n"], 4) if combined_trad["n"] else None,
            "ce_n": combined_ce["n"],
            "ce_asr": round(combined_ce["succ"] / combined_ce["n"], 4) if combined_ce["n"] else None,
            "delta_ce_minus_trad": None,
            "mcnemar_b_trad_only": None,
            "mcnemar_c_ce_only": None,
            "mcnemar_p_exact": None,
        }
    )
    pd.DataFrame(recs).to_csv(out, index=False)


def _mcnemar_bc(trad: pd.DataFrame, ce: pd.DataFrame) -> tuple[int, int]:
    tk = {(r.task_seed, r.payload_variant): bool(r.attack_success) for r in trad.itertuples()}
    ck = {(r.task_seed, r.payload_variant): bool(r.attack_success) for r in ce.itertuples()}
    keys = set(tk) & set(ck)
    b = sum(1 for k in keys if tk[k] and not ck[k])  # trad-only success
    c = sum(1 for k in keys if ck[k] and not tk[k])  # ce-only success
    return b, c


def _mcnemar_exact(b: int, c: int) -> float:
    n = b + c
    if n == 0:
        return 1.0
    try:
        from scipy.stats import binomtest

        return float(binomtest(min(b, c), n, 0.5).pvalue)
    except Exception:  # noqa: BLE001
        from math import comb

        k = min(b, c)
        tail = sum(comb(n, i) for i in range(0, k + 1)) * (0.5 ** n)
        return min(1.0, 2 * tail)


def clean_utility(all_rows: dict[str, list[dict]], out: Path) -> None:
    recs = []
    for model_key, rows in all_rows.items():
        rows = [r for r in _valid(rows) if r.get("task_type") == "clean"]
        df = pd.DataFrame(rows)
        if df.empty:
            continue
        for (arch, defense), g in df.groupby(["architecture", "defense_config"]):
            n = len(g)
            succ = int(g["correct_benign_result"].sum())
            p, lo, hi = wilson_ci(succ, n)
            recs.append(
                {
                    "model_key": model_key,
                    "architecture": arch,
                    "defense_config": defense,
                    "n": n,
                    "clean_success": round(p, 4),
                    "clean_success_str": _fmt_ci(succ, n),
                    "mean_latency_s": round(float(g["latency_seconds"].mean()), 3),
                }
            )
    pd.DataFrame(recs).to_csv(out, index=False)


def trial_counts(all_rows: dict[str, list[dict]], out: Path) -> dict[str, Any]:
    recs = []
    totals = {"valid": 0, "infra": 0}
    for model_key, rows in all_rows.items():
        valid = _valid(rows)
        infra = [r for r in rows if r.get("trial_status") == "infrastructure_failure"]
        ce_adv = [r for r in valid if r.get("task_type") == "attack" and r.get("architecture") == "cemcp"]
        trad_adv = [r for r in valid if r.get("task_type") == "attack" and r.get("architecture") == "traditional_mcp"]
        clean = [r for r in valid if r.get("task_type") == "clean"]
        recs.append(
            {
                "model_key": model_key,
                "ce_adversarial": len(ce_adv),
                "ce_adversarial_expected": EXPECTED_CE_ADVERSARIAL,
                "trad_adversarial": len(trad_adv),
                "trad_adversarial_expected": EXPECTED_TRAD_ADVERSARIAL,
                "clean": len(clean),
                "clean_expected": EXPECTED_CLEAN,
                "infrastructure_failures": len(infra),
                "missing_ce_adv": max(0, EXPECTED_CE_ADVERSARIAL - len(ce_adv)),
                "missing_trad_adv": max(0, EXPECTED_TRAD_ADVERSARIAL - len(trad_adv)),
                "missing_clean": max(0, EXPECTED_CLEAN - len(clean)),
            }
        )
        totals["valid"] += len(valid)
        totals["infra"] += len(infra)
    pd.DataFrame(recs).to_csv(out, index=False)
    return totals


def infrastructure_failures(all_rows: dict[str, list[dict]], out: Path) -> None:
    recs = []
    for model_key, rows in all_rows.items():
        for r in rows:
            if r.get("trial_status") == "infrastructure_failure":
                recs.append(
                    {
                        "model_key": model_key,
                        "trial_id": r.get("trial_id"),
                        "attack_id": r.get("attack_id"),
                        "errors": "; ".join(r.get("errors", []))[:300],
                    }
                )
    pd.DataFrame(recs or [{"model_key": None, "trial_id": None, "attack_id": None, "errors": None}]).to_csv(
        out, index=False
    )


def parser_failures(all_rows: dict[str, list[dict]], out: Path) -> None:
    recs = []
    for model_key, rows in all_rows.items():
        valid = _valid(rows)
        n = len(valid)
        parse_fail = sum(
            1
            for r in valid
            if any("parse" in (e or "").lower() for e in (r.get("errors") or []))
        )
        recs.append(
            {
                "model_key": model_key,
                "n": n,
                "tool_parse_failures": parse_fail,
                "tool_parse_failure_rate": round(parse_fail / n, 4) if n else 0.0,
            }
        )
    pd.DataFrame(recs).to_csv(out, index=False)


def replay_agreement(results_root: Path, out: Path) -> None:
    path = results_root / "python_replay_gpt54" / "replay.jsonl"
    rows = read_jsonl(path)
    if not rows:
        pd.DataFrame([{"note": "no replay results yet"}]).to_csv(out, index=False)
        return
    df = pd.DataFrame(rows)
    attacks = df[df["task_type"] == "attack"]
    summary = {
        "total": len(df),
        "adversarial": len(attacks),
        "clean": int((df["task_type"] == "clean").sum()),
        "verdict_agreement": int(attacks["verdict_agreement"].fillna(False).sum()),
        "verdict_agreement_rate": round(float(attacks["verdict_agreement"].fillna(False).mean()), 4) if len(attacks) else None,
        "result_agreement_rate": round(float(df["result_agreement"].fillna(False).mean()), 4),
        "python_only_success": int(df["python_only_success"].fillna(False).sum()),
        "ast_only_success": int(df["ast_only_success"].fillna(False).sum()),
        "policy_mismatch": int(df["policy_mismatch"].fillna(False).sum()),
        "timeouts": int(df["timeout"].fillna(False).sum()),
    }
    pd.DataFrame([summary]).to_csv(out, index=False)


def p55_budget(results_root: Path, out: Path) -> None:
    path = results_root / "p55_budget_gpt54" / "trials.jsonl"
    rows = [r for r in read_jsonl(path) if r.get("trial_status", "valid") == "valid"]
    if not rows:
        pd.DataFrame([{"note": "no p55 results yet"}]).to_csv(out, index=False)
        return
    df = pd.DataFrame(rows)
    recs = []
    for budget_label, g in df.groupby("defense_config"):
        mal = g[g["task_type"] == "attack"]
        ben = g[g["task_type"] == "clean"]
        # amplification: matched by (seed,variant) attacked/benign model_calls
        amp = _amplification(mal, ben)
        n_mal = len(mal)
        succ = int(mal["attack_success"].sum())
        p, lo, hi = wilson_ci(succ, n_mal) if n_mal else (0, 0, 0)
        stcr_succ = int(mal["secure_task_completion"].sum())
        ben_succ = int(ben["correct_benign_result"].sum())
        exhaustion = float((mal["agent_regeneration_count"] >= mal["agent_regeneration_budget"]).mean()) if n_mal else 0.0
        recs.append(
            {
                "budget_label": budget_label,
                "budget": int(mal["agent_regeneration_budget"].iloc[0]) if n_mal else None,
                "n_malicious": n_mal,
                "asr": round(p, 4),
                "asr_str": _fmt_ci(succ, n_mal),
                "stcr": round(stcr_succ / n_mal, 4) if n_mal else None,
                "stcr_str": _fmt_ci(stcr_succ, n_mal),
                "n_benign": len(ben),
                "benign_success": round(ben_succ / len(ben), 4) if len(ben) else None,
                "benign_success_str": _fmt_ci(ben_succ, len(ben)) if len(ben) else None,
                "median_regen": float(mal["agent_regeneration_count"].median()) if n_mal else None,
                "mean_regen": round(float(mal["agent_regeneration_count"].mean()), 3) if n_mal else None,
                "median_model_calls": float(mal["model_call_count"].median()) if n_mal else None,
                "mean_model_calls": round(float(mal["model_call_count"].mean()), 3) if n_mal else None,
                "median_latency_s": round(float(mal["latency_seconds"].median()), 3) if n_mal else None,
                "mean_output_tokens": round(float(mal["output_tokens"].mean()), 1) if n_mal else None,
                "budget_exhaustion_rate": round(exhaustion, 4),
                "regeneration_amplification": amp,
            }
        )
    recs.sort(key=lambda r: (r["budget"] or 0))
    pd.DataFrame(recs).to_csv(out, index=False)


def _amplification(mal: pd.DataFrame, ben: pd.DataFrame) -> float | None:
    def key(r):
        tid = r.trial_id
        return tid.split("__seed")[-1] if "__seed" in tid else tid
    mk = {key(r): r.model_call_count for r in mal.itertuples()}
    bk = {key(r): r.model_call_count for r in ben.itertuples()}
    ratios = [mk[k] / bk[k] for k in (set(mk) & set(bk)) if bk[k]]
    return round(sum(ratios) / len(ratios), 3) if ratios else None


def write_latex(summary_dir: Path) -> None:
    lines = ["% Auto-generated paper tables (AIDC CE-MCP revision)"]
    ladder = summary_dir / "defense_ladder.csv"
    if ladder.exists():
        df = pd.read_csv(ladder)
        four = df[(df["model_key"] == "FOUR_MODEL_MACRO")]
        lines.append("\\begin{tabular}{lc}")
        lines.append("\\toprule Defense & 4-model macro ASR \\\\ \\midrule")
        for _, r in four.iterrows():
            lines.append(f"{r['defense_config']} & {100 * r['asr']:.1f}\\% \\\\")
        lines.append("\\bottomrule\\end{tabular}")
    (summary_dir / "paper_tables.tex").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-root", default="results/aidc_revision_2026")
    args = parser.parse_args()

    results_root = ROOT / args.results_root
    summary_dir = ensure_dir(results_root / "summary")

    all_rows: dict[str, list[dict]] = {}
    for mk in PAPER_MODELS + SECONDARY_MODELS:
        rows = _load_model(results_root, mk)
        if rows:
            all_rows[mk] = rows

    if not all_rows:
        print(f"No model results found under {results_root}")
        return 1

    per_attack_per_model(all_rows, summary_dir / "per_attack_per_model.csv")
    defense_ladder(all_rows, summary_dir / "defense_ladder.csv")
    architecture_comparison(all_rows, summary_dir / "architecture_comparison.csv")
    clean_utility(all_rows, summary_dir / "clean_utility.csv")
    parser_failures(all_rows, summary_dir / "parser_failures.csv")
    infrastructure_failures(all_rows, summary_dir / "infrastructure_failures.csv")
    trial_counts(all_rows, summary_dir / "trial_counts.csv")
    replay_agreement(results_root, summary_dir / "python_replay_agreement.csv")
    p55_budget(results_root, summary_dir / "p55_budget_sensitivity.csv")
    write_latex(summary_dir)

    print("Aggregation complete. Outputs in", summary_dir)
    for f in sorted(summary_dir.glob("*")):
        print("  -", f.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
