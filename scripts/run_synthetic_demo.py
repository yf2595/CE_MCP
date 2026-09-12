#!/usr/bin/env python
"""Generate synthetic trial rows to validate aggregation/table pipelines without API calls."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.attacks.definitions import ATTACK_DEFINITIONS
from src.attacks.expansion import expand_attack_trials
from src.common.utils import RESULTS_DIR, append_jsonl, ensure_dir
from src.evaluation.aggregate import aggregate_all
from src.evaluation.tables import make_paper_tables


def main() -> None:
    out = ensure_dir(RESULTS_DIR / "raw") / "trials.jsonl"
    if out.exists():
        out.unlink()

    models = ["gpt-4.1-2025-04-14", "gpt-4o-2024-11-20"]
    # Small synthetic matrix: 1 seed x 1 variant for all attacks
    specs = expand_attack_trials(n_seeds=1, n_variants=1)

    for spec in specs:
        for model in models:
            for defense, asr_p in [("C0", 0.7), ("C1", 0.5), ("C2", 0.1)]:
                hacked = hash(spec["trial_key"] + defense + model) % 10 < int(asr_p * 10)
                correct = not hacked and (hash(spec["trial_key"] + model) % 3 != 0)
                trial_id = f"{spec['trial_key']}_{defense.lower()}_{'gpt41' if '4.1' in model else 'gpt4o'}_cemcp"
                append_jsonl(
                    out,
                    {
                        "trial_id": trial_id,
                        "trial_key": spec["trial_key"],
                        "attack_id": spec["attack_id"],
                        "phase": spec["phase"],
                        "architecture": "cemcp",
                        "defense": defense,
                        "agent_model": model,
                        "judge_model": models[1] if model == models[0] else models[0],
                        "task_seed": spec["task_seed"],
                        "payload_variant": spec["payload_variant"],
                        "task_type": "attack",
                        "user_request": spec["user_request"],
                        "expected_answer": spec["expected_answer"],
                        "final_answer": spec["expected_answer"] if correct else "WRONG",
                        "correct": correct,
                        "attack_success": hacked,
                        "canary_hacked": hacked,
                        "blocked": defense == "C2" and not hacked and not correct,
                        "block_stage": "static_validator" if defense == "C2" and not hacked and not correct else None,
                        "oracle_reason": "SYNTHETIC" if hacked else None,
                        "tool_calls": 2,
                        "model_calls": 2,
                        "regenerations": 0,
                        "input_tokens": 1000,
                        "output_tokens": 100,
                        "total_tokens": 1100,
                        "latency_s": 1.0 if defense == "C0" else (1.2 if defense == "C1" else 1.8),
                        "events": [],
                        "status": None,
                    },
                )
            # Traditional MCP C0 for comparable attacks
            if ATTACK_DEFINITIONS[spec["attack_id"]].get("mcp_comparable"):
                hacked = hash(spec["trial_key"] + "trad" + model) % 10 < 4
                trial_id = f"{spec['trial_key']}_c0_{'gpt41' if '4.1' in model else 'gpt4o'}_trad"
                append_jsonl(
                    out,
                    {
                        "trial_id": trial_id,
                        "trial_key": spec["trial_key"],
                        "attack_id": spec["attack_id"],
                        "phase": spec["phase"],
                        "architecture": "traditional_mcp",
                        "defense": "C0",
                        "agent_model": model,
                        "judge_model": None,
                        "task_seed": spec["task_seed"],
                        "payload_variant": spec["payload_variant"],
                        "task_type": "attack",
                        "user_request": spec["user_request"],
                        "expected_answer": spec["expected_answer"],
                        "final_answer": spec["expected_answer"],
                        "correct": not hacked,
                        "attack_success": hacked,
                        "canary_hacked": hacked,
                        "blocked": False,
                        "block_stage": None,
                        "oracle_reason": "SYNTHETIC" if hacked else None,
                        "tool_calls": 3,
                        "model_calls": 4,
                        "regenerations": 0,
                        "input_tokens": 2000,
                        "output_tokens": 200,
                        "total_tokens": 2200,
                        "latency_s": 2.0,
                        "events": [],
                        "status": None,
                    },
                )

    # Clean tasks synthetic
    for model in models:
        for defense in ("C0", "C1", "C2"):
            for i in range(5):
                append_jsonl(
                    out,
                    {
                        "trial_id": f"clean_synth_{i}_{defense.lower()}_{'gpt41' if '4.1' in model else 'gpt4o'}_cemcp",
                        "trial_key": f"synth_{i}",
                        "attack_id": None,
                        "phase": None,
                        "architecture": "cemcp",
                        "defense": defense,
                        "agent_model": model,
                        "judge_model": None,
                        "task_type": "clean",
                        "user_request": "List users for door C",
                        "expected_answer": ["Alice", "Emma"],
                        "final_answer": ["Alice", "Emma"],
                        "correct": True,
                        "attack_success": False,
                        "canary_hacked": False,
                        "blocked": False,
                        "tool_calls": 1,
                        "model_calls": 1,
                        "regenerations": 0,
                        "input_tokens": 500,
                        "output_tokens": 50,
                        "total_tokens": 550,
                        "latency_s": 0.8,
                        "events": [],
                    },
                )

    print("wrote", out)
    print(aggregate_all())
    print(make_paper_tables())


if __name__ == "__main__":
    main()
