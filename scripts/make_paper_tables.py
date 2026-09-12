#!/usr/bin/env python
"""Generate paper tables from raw results."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.evaluation.tables import make_paper_tables


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default=None,
        help="Path to raw trials JSONL (default: results/raw/trials.jsonl)",
    )
    args = parser.parse_args()
    trials_path = Path(args.input) if args.input else None
    outputs = make_paper_tables(trials_path)
    for k, v in outputs.items():
        print(k, "->", v)


if __name__ == "__main__":
    main()
