#!/usr/bin/env python
"""Run clean utility evaluation."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.attacks.clean_tasks import load_clean_tasks
from src.common.logging import setup_logging
from src.common.utils import RESULTS_DIR, ensure_dir
from src.evaluation.runner import load_experiment_config, run_clean_trial


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--architecture", default="cemcp", choices=["cemcp", "traditional_mcp", "both"])
    parser.add_argument("--defense", default="all", choices=["C0", "C1", "C2", "all"])
    parser.add_argument("--model", default="all")
    parser.add_argument(
        "--output",
        default=None,
        help="Path to trials JSONL (default: results/raw/trials.jsonl). "
        "Point at the attack run's file to aggregate clean + attack together.",
    )
    args = parser.parse_args()
    log = setup_logging()
    cfg = load_experiment_config()
    tasks = load_clean_tasks()
    if args.limit:
        tasks = tasks[: args.limit]
    models = cfg["models"] if args.model == "all" else [args.model]
    defenses = cfg["ce_defenses"] if args.defense == "all" else [args.defense]
    arches = ["cemcp", "traditional_mcp"] if args.architecture == "both" else [args.architecture]

    results_path = Path(args.output) if args.output else (RESULTS_DIR / "raw" / "trials.jsonl")
    ensure_dir(results_path.parent)

    for arch in arches:
        for model in models:
            for defense in defenses:
                if arch == "traditional_mcp" and defense != "C0":
                    continue
                for task in tasks:
                    log.info("clean %s %s %s %s", arch, defense, model, task["task_id"])
                    run_clean_trial(
                        task,
                        architecture=arch,
                        defense=defense,
                        agent_model=model,
                        config=cfg,
                        results_path=results_path,
                    )
    print("done")
    print("results:", results_path)


if __name__ == "__main__":
    main()
