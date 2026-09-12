#!/usr/bin/env python
"""Poll a local vLLM OpenAI-compatible server until /v1/models responds."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True, help="e.g. http://127.0.0.1:18000/v1")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--expected-model", default=None)
    args = parser.parse_args()

    url = args.base_url.rstrip("/") + "/models"
    deadline = time.time() + args.timeout_seconds
    last_err = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            names = [m.get("id") for m in data.get("data", [])]
            print(f"vLLM healthy at {url}; models={names}")
            if args.expected_model and args.expected_model not in names:
                print(
                    f"WARNING expected model {args.expected_model!r} not in {names}",
                    file=sys.stderr,
                )
            return 0
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            time.sleep(5)
    print(f"vLLM did not become healthy within {args.timeout_seconds}s: {last_err}", file=sys.stderr)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
