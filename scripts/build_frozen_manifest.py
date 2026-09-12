#!/usr/bin/env python
"""Build (or rebuild) artifacts/frozen_suite_manifest.json.

Run this once before the paper runs, after confirming the experimental inputs are
final. Re-running after an intentional change is the ONLY sanctioned way to move
the frozen baseline; do not edit the manifest by hand.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.validation.frozen_manifest import MANIFEST_PATH, write_manifest


def main() -> int:
    manifest = write_manifest()
    print(f"Wrote {MANIFEST_PATH.relative_to(ROOT)}")
    print(f"  frozen files:  {len(manifest['entries'])}")
    print(f"  suite hash:    {manifest['suite_manifest_sha256']}")
    if manifest["missing"]:
        print("  WARNING missing expected files:")
        for m in manifest["missing"]:
            print(f"    - {m}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
