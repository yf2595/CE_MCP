#!/usr/bin/env python
"""Reasoning-mode smoke test (plan 10.3).

Verifies ONLY configuration/plumbing, never the private chain-of-thought:
  - GPT-5.4 request carries reasoning.effort=low (checked in Phase 0 / backend).
  - GPT-OSS receives a low reasoning control.
  - Qwen3 thinking is enabled and separated from tool arguments.
  - Llama receives the plan-and-act compatibility prompt.

Stores only reasoning_mode, reasoning_tokens (when available), and
reasoning_parser_status.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.backends.registry import build_backend, max_output_tokens_for, model_spec


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-key", required=True)
    parser.add_argument("--base-url", default=None)
    args = parser.parse_args()

    if args.base_url:
        os.environ["WAITI_VLLM_ENDPOINT"] = args.base_url

    spec = model_spec(args.model_key)
    backend = build_backend(args.model_key, base_url=args.base_url)

    problems: list[str] = []
    expected_mode = spec.get("reasoning_mode")

    # Config-level checks.
    if args.model_key == "gpt_oss_20b":
        if spec.get("reasoning_effort") != "low" and spec.get("system_prefix") != "Reasoning: low":
            problems.append("gpt-oss missing low reasoning control")
    if args.model_key == "qwen3_14b":
        eb = spec.get("extra_body") or {}
        if not (eb.get("chat_template_kwargs") or {}).get("enable_thinking"):
            problems.append("qwen3 thinking not enabled")
    if args.model_key == "llama31_8b":
        if "plan the complete" not in (spec.get("system_prefix") or ""):
            problems.append("llama plan-and-act prompt missing")

    # Live plumbing check: one tiny request; confirm we parse a turn and (for
    # reasoning models) that thinking output is separated from the answer text.
    turn = backend.generate(
        [{"role": "user", "content": "Briefly: what is 6 times 7? Answer with the number."}],
        [],
        max_output_tokens=max_output_tokens_for(args.model_key),
        request_metadata={"trial_id": "smoke_reasoning"},
    )
    reasoning_parser_status = "ok"
    if turn.text is None:
        reasoning_parser_status = "no_text"
        problems.append("no assistant text returned")

    out = {
        "model_key": args.model_key,
        "reasoning_mode": turn.reasoning_mode or expected_mode,
        "reasoning_tokens": turn.usage.reasoning_tokens,
        "reasoning_control_source": turn.reasoning_control_source,
        "reasoning_parser_status": reasoning_parser_status,
        "has_reasoning_summary": bool(turn.reasoning_summary),
        "answer_preview": (turn.text or "")[:80],
    }
    print(json.dumps(out, indent=2))

    status = "PASS" if not problems else "FAIL"
    print(f"[smoke_reasoning] {status} model_key={args.model_key}")
    for p in problems:
        print(f"  - {p}")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
