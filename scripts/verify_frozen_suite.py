#!/usr/bin/env python
"""Verify the frozen experimental suite before a run.

Exit 0 = suite matches the manifest. Exit 3 = drift detected (abort the run)
unless the operator passes --allow-suite-mismatch (never use for paper runs).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.validation.frozen_manifest import verify_manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--allow-suite-mismatch",
        action="store_true",
        help="Proceed even if frozen files drifted (NOT for paper runs).",
    )
    args = parser.parse_args()

    ok, problems = verify_manifest()
    if ok:
        print("Frozen suite: PASS (all frozen inputs match the manifest).")
        return 0

    print("Frozen suite: FAIL")
    for p in problems:
        print(f"  - {p}")
    if args.allow_suite_mismatch:
        print("\n--allow-suite-mismatch set: proceeding despite drift.")
        return 0
    print("\nAborting. Rebuild intentionally with scripts/build_frozen_manifest.py")
    print("or pass --allow-suite-mismatch for a non-paper run.")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
