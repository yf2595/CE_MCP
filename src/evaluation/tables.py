"""Generate paper-ready tables."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.attacks.definitions import ATTACK_DEFINITIONS
from src.common.utils import RESULTS_DIR, ensure_dir, read_jsonl
from src.evaluation.metrics import asr, clean_success, filter_trials, mean_latency, stcr


def _fmt_pct(x: float | None) -> str:
    if x is None:
        return "N/A"
    return f"{100 * x:.1f}\\%"


def make_paper_tables(trials_path: Path | None = None) -> dict[str, Path]:
    path = trials_path or (RESULTS_DIR / "raw" / "trials.jsonl")
    rows = read_jsonl(path)
    tables = ensure_dir(RESULTS_DIR / "tables")
    outputs: dict[str, Path] = {}

    # Table 1 — attack surface
    lines = [
        r"\begin{tabular}{llrrr}",
        r"\hline",
        r"Threat & Relation & MCP ASR & CE-MCP ASR & CE-MCP 95\% CI \\",
        r"\hline",
    ]
    md_lines = ["| Threat | Relation | MCP ASR | CE-MCP ASR | CE-MCP 95% CI |", "|---|---|---:|---:|---:|"]
    for attack_id, meta in ATTACK_DEFINITIONS.items():
        mcp = filter_trials(rows, task_type="attack", attack_id=attack_id, architecture="traditional_mcp", defense="C0")
        ce = filter_trials(rows, task_type="attack", attack_id=attack_id, architecture="cemcp", defense="C0")
        if meta.get("mcp_comparable") and mcp:
            mcp_asr = _fmt_pct(asr(mcp)["asr"])
        else:
            mcp_asr = "N/A"
        if ce:
            a = asr(ce)
            ce_asr = _fmt_pct(a["asr"])
            ci = f"[{100 * a['asr_low']:.1f}, {100 * a['asr_high']:.1f}]"
        else:
            ce_asr, ci = "—", "—"
        rel = meta["relation"].replace("%", r"\%")
        lines.append(f"{attack_id} & {rel} & {mcp_asr} & {ce_asr} & {ci} \\\\")
        md_lines.append(f"| {attack_id} | {meta['relation']} | {mcp_asr} | {ce_asr} | {ci} |")
    lines.extend([r"\hline", r"\end{tabular}"])
    p1 = tables / "table_attack_surface.tex"
    p1.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (tables / "table_attack_surface.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    outputs["table_attack_surface"] = p1

    # Table 2 — defense
    lines2 = [
        r"\begin{tabular}{lrrrr}",
        r"\hline",
        r"Defense & ASR $\downarrow$ & STCR $\uparrow$ & Clean Success $\uparrow$ & Latency \\",
        r"\hline",
    ]
    md2 = ["| Defense | ASR ↓ | STCR ↑ | Clean Success ↑ | Latency |", "|---|---:|---:|---:|---:|"]
    c0 = filter_trials(rows, task_type="attack", architecture="cemcp", defense="C0")
    base_lat = mean_latency(c0) or 1e-9
    for defense in ("C0", "C1", "C2"):
        subset = filter_trials(rows, task_type="attack", architecture="cemcp", defense=defense)
        clean = filter_trials(rows, task_type="clean", architecture="cemcp", defense=defense)
        if not subset:
            continue
        a = asr(subset)
        s = stcr(subset)
        cs = clean_success(clean)["clean_success"] if clean else None
        lat = mean_latency(subset) / base_lat
        label = r"\textbf{C2 Full}" if defense == "C2" else defense
        lines2.append(
            f"{label} & {_fmt_pct(a['asr'])} & {_fmt_pct(s['stcr'])} & {_fmt_pct(cs)} & {lat:.2f}x \\\\"
        )
        md2.append(
            f"| {defense} | {_fmt_pct(a['asr'])} | {_fmt_pct(s['stcr'])} | {_fmt_pct(cs)} | {lat:.2f}x |"
        )
    lines2.extend([r"\hline", r"\end{tabular}"])
    p2 = tables / "table_defense.tex"
    p2.write_text("\n".join(lines2) + "\n", encoding="utf-8")
    (tables / "table_defense.md").write_text("\n".join(md2) + "\n", encoding="utf-8")
    outputs["table_defense"] = p2

    # Table 3 — model robustness
    lines3 = [
        r"\begin{tabular}{lrrrr}",
        r"\hline",
        r"Model & C0 ASR & C2 ASR & C2 STCR & Clean Success \\",
        r"\hline",
    ]
    md3 = ["| Model | C0 ASR | C2 ASR | C2 STCR | Clean Success |", "|---|---:|---:|---:|---:|"]
    models = sorted({r["agent_model"] for r in rows if r.get("agent_model")})
    for model in models:
        c0m = filter_trials(rows, task_type="attack", architecture="cemcp", defense="C0", agent_model=model)
        c2m = filter_trials(rows, task_type="attack", architecture="cemcp", defense="C2", agent_model=model)
        clean = filter_trials(rows, task_type="clean", architecture="cemcp", defense="C2", agent_model=model)
        lines3.append(
            f"{model} & {_fmt_pct(asr(c0m)['asr'] if c0m else None)} & "
            f"{_fmt_pct(asr(c2m)['asr'] if c2m else None)} & "
            f"{_fmt_pct(stcr(c2m)['stcr'] if c2m else None)} & "
            f"{_fmt_pct(clean_success(clean)['clean_success'] if clean else None)} \\\\"
        )
        md3.append(
            f"| {model} | {_fmt_pct(asr(c0m)['asr'] if c0m else None)} | "
            f"{_fmt_pct(asr(c2m)['asr'] if c2m else None)} | "
            f"{_fmt_pct(stcr(c2m)['stcr'] if c2m else None)} | "
            f"{_fmt_pct(clean_success(clean)['clean_success'] if clean else None)} |"
        )
    lines3.extend([r"\hline", r"\end{tabular}"])
    p3 = tables / "table_model_robustness.tex"
    p3.write_text("\n".join(lines3) + "\n", encoding="utf-8")
    (tables / "table_model_robustness.md").write_text("\n".join(md3) + "\n", encoding="utf-8")
    outputs["table_model_robustness"] = p3
    return outputs
