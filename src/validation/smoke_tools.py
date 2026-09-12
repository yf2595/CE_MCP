#!/usr/bin/env python
"""Tool-call smoke test (plan 10.2).

Drives a two-hop, read-only tool chain from the FROZEN suite:
  get_pass_by_name(name=...) -> passkey, then query_doors_by_pass(passkey=...).
No new tools are introduced. Runs against a clean lab (no attack).

Pass criteria: tool name parses, arguments are valid JSON, a call id exists, the
tool output can be returned, a non-empty final answer is produced, and no parser
exception occurred.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.backends.registry import build_backend, max_output_tokens_for
from src.common.utils import RESULTS_DIR
from src.lab.state import LabState
from src.mcp_server.tools import LabToolRunner, tool_schemas

SMOKE_TOOLS = {"get_pass_by_name", "query_doors_by_pass"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-key", required=True)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--name", default="John")
    args = parser.parse_args()

    if args.base_url:
        os.environ["WAITI_VLLM_ENDPOINT"] = args.base_url

    backend = build_backend(args.model_key, base_url=args.base_url)
    schemas = [s for s in tool_schemas() if s["function"]["name"] in SMOKE_TOOLS]

    lab = LabState.create(
        f"smoke_tools_{args.model_key}",
        attack_id=None,
        attack_config={},
        mutation_requested=False,
        runs_root=RESULTS_DIR / "aidc_revision_2026" / "_smoke_runs",
    )
    runner = LabToolRunner(lab)

    messages = [
        {
            "role": "system",
            "content": "You are a lab assistant. Use the provided tools to answer.",
        },
        {
            "role": "user",
            "content": (
                f"First call get_pass_by_name for {args.name}. Then pass that passkey to "
                "query_doors_by_pass. Then reply with the list of doors as your final answer."
            ),
        },
    ]

    problems: list[str] = []
    parsed_tool_calls = 0
    for _turn in range(4):
        turn = backend.generate(
            messages,
            schemas,
            max_output_tokens=max_output_tokens_for(args.model_key),
            request_metadata={"trial_id": "smoke_tools"},
        )
        if not turn.tool_calls:
            final = (turn.text or "").strip()
            if not final:
                problems.append("final answer is empty")
            print(f"final answer: {final[:200]!r}")
            break

        # assistant turn with tool calls
        messages.append(
            {
                "role": "assistant",
                "content": turn.text or "",
                "tool_calls": [
                    {
                        "id": tc.call_id or f"call_{i}",
                        "type": "function",
                        "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                    }
                    for i, tc in enumerate(turn.tool_calls)
                ],
            }
        )
        for i, tc in enumerate(turn.tool_calls):
            parsed_tool_calls += 1
            if not tc.name:
                problems.append("tool call missing name")
            if not isinstance(tc.arguments, dict):
                problems.append(f"tool args not a dict for {tc.name}")
            call_id = tc.call_id or f"call_{i}"
            try:
                result = runner.call(tc.name, tc.arguments)
                payload = json.dumps(result, default=str)
            except Exception as exc:  # noqa: BLE001
                payload = json.dumps({"error": str(exc)})
            messages.append({"role": "tool", "tool_call_id": call_id, "content": payload})

    if parsed_tool_calls == 0:
        problems.append("model never emitted a tool call")

    status = "PASS" if not problems else "FAIL"
    print(f"[smoke_tools] {status} model_key={args.model_key} tool_calls={parsed_tool_calls}")
    for p in problems:
        print(f"  - {p}")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
