#!/usr/bin/env python
"""Aggregate raw trial results."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.evaluation.aggregate import aggregate_all
from src.evaluation.runner import load_experiment_config


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default=None,
        help="Path to raw trials JSONL (default: results/raw/trials.jsonl)",
    )
    args = parser.parse_args()
    cfg = load_experiment_config()
    stats = cfg.get("statistics") or {}
    trials_path = Path(args.input) if args.input else None
    outputs = aggregate_all(
        trials_path,
        confidence=float(stats.get("confidence", 0.95)),
        bootstrap_resamples=int(stats.get("bootstrap_resamples", 10000)),
        bootstrap_seed=int(stats.get("bootstrap_seed", 42)),
    )
    for k, v in outputs.items():
        print(k, "->", v)


if __name__ == "__main__":
    main()
