#!/usr/bin/env python
"""Validate a result JSONL directory (plan 15.1) after a run.

Checks each v2.0 record for required fields, reports duplicate trial IDs,
infrastructure failures, parser failures, and canary/oracle consistency.
Exit non-zero if hard problems (duplicates / schema) are found.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.common.utils import read_jsonl

REQUIRED = [
    "schema_version",
    "trial_id",
    "model_key",
    "architecture",
    "defense_config",
    "task_type",
    "trial_status",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result-root", required=True)
    args = parser.parse_args()

    root = Path(args.result_root)
    files = sorted(root.glob("*.jsonl")) or ([root] if root.suffix == ".jsonl" else [])
    if not files:
        print(f"[validate_logs] no JSONL under {root}")
        return 1

    rows = []
    for f in files:
        rows.extend(read_jsonl(f))

    ids = [r.get("trial_id") for r in rows if r.get("trial_id")]
    dupes = [tid for tid, c in Counter(ids).items() if c > 1]
    missing_fields = 0
    infra = 0
    valid = 0
    canary_mismatch = 0
    for r in rows:
        if any(k not in r for k in REQUIRED):
            missing_fields += 1
        status = r.get("trial_status")
        if status == "infrastructure_failure":
            infra += 1
        elif status == "valid":
            valid += 1
        if r.get("task_type") == "attack" and "canary_hacked" in r:
            if bool(r.get("attack_success")) != bool(r.get("canary_hacked")):
                canary_mismatch += 1

    print(f"[validate_logs] files={len(files)} records={len(rows)}")
    print(f"  valid={valid} infrastructure_failures={infra}")
    print(f"  duplicate_trial_ids={len(dupes)}")
    print(f"  records_missing_required_fields={missing_fields}")
    print(f"  canary/oracle mismatches={canary_mismatch}")
    if dupes:
        for d in dupes[:20]:
            print(f"    DUP {d}")

    hard = len(dupes) + missing_fields + canary_mismatch
    return 0 if hard == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
