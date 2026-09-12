#!/usr/bin/env python
"""Phase 0 access probe for the AIDC CE-MCP revision.

Checks, against the operator's OPENAI_API_KEY, whether:
  1. The OpenAI Responses API accepts `gpt-5.4` with reasoning.effort="low".
  2. The Chat Completions API accepts `gpt-5.4` (fallback path).
  3. The retained legacy model `gpt-4.1-2025-04-14` still works (Chat Completions).

It prints a compact capability report and writes it to
`artifacts/gpt54_access_probe.json`. The API key is never printed or stored.

Exit code 0 means at least one GPT-5.4 path works; non-zero means neither did.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

GPT54 = os.environ.get("GPT54_MODEL", "gpt-5.4")
GPT41 = os.environ.get("GPT41_MODEL", "gpt-4.1-2025-04-14")


def _short_err(exc: Exception) -> str:
    """Return a short, key-free error description."""
    msg = f"{type(exc).__name__}: {exc}"
    return msg[:400]


def probe_responses_low(client, model: str) -> dict:
    try:
        resp = client.responses.create(
            model=model,
            input="Reply with the single word: OK",
            reasoning={"effort": "low"},
            max_output_tokens=64,
            store=False,
        )
        text = getattr(resp, "output_text", None)
        return {
            "ok": True,
            "returned_model": getattr(resp, "model", None),
            "request_id": getattr(resp, "_request_id", None) or getattr(resp, "id", None),
            "sample_text": (text or "")[:80],
        }
    except Exception as exc:  # noqa: BLE001 - report every failure explicitly
        return {"ok": False, "error": _short_err(exc)}


def probe_chat(client, model: str, *, reasoning: bool = False) -> dict:
    kwargs = {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with the single word: OK"}],
        "max_tokens": 64,
    }
    if reasoning:
        # Some reasoning models only accept reasoning_effort on chat completions.
        kwargs["reasoning_effort"] = "low"
    try:
        resp = client.chat.completions.create(**kwargs)
        return {
            "ok": True,
            "returned_model": getattr(resp, "model", None),
            "request_id": getattr(resp, "_request_id", None) or getattr(resp, "id", None),
            "sample_text": (resp.choices[0].message.content or "")[:80],
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": _short_err(exc)}


def main() -> int:
    load_dotenv(ROOT / ".env")
    key = os.environ.get("OPENAI_API_KEY")
    if not key or key.startswith("sk-your-key"):
        print("ERROR: OPENAI_API_KEY is not set (or still the placeholder).")
        return 2

    import openai
    from openai import OpenAI

    client = OpenAI(api_key=key)

    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "openai_sdk_version": getattr(openai, "__version__", "unknown"),
        "models": {"gpt54": GPT54, "gpt41": GPT41},
        "probes": {},
    }

    print(f"openai SDK version: {report['openai_sdk_version']}")
    print(f"Probing GPT-5.4 ({GPT54}) via Responses API (reasoning.effort=low) ...")
    report["probes"]["gpt54_responses_low"] = probe_responses_low(client, GPT54)

    print(f"Probing GPT-5.4 ({GPT54}) via Chat Completions ...")
    report["probes"]["gpt54_chat"] = probe_chat(client, GPT54)

    print(f"Probing GPT-5.4 ({GPT54}) via Chat Completions + reasoning_effort=low ...")
    report["probes"]["gpt54_chat_reasoning"] = probe_chat(client, GPT54, reasoning=True)

    print(f"Probing legacy GPT-4.1 ({GPT41}) via Chat Completions ...")
    report["probes"]["gpt41_chat"] = probe_chat(client, GPT41)

    responses_ok = report["probes"]["gpt54_responses_low"]["ok"]
    chat_ok = report["probes"]["gpt54_chat"]["ok"] or report["probes"]["gpt54_chat_reasoning"]["ok"]

    if responses_ok:
        recommendation = "openai_responses (reasoning.effort=low)"
    elif chat_ok:
        recommendation = "openai_chat (fallback; reasoning_effort=low if accepted)"
    else:
        recommendation = "NONE - gpt-5.4 not reachable with this key"
    report["recommended_gpt54_backend"] = recommendation

    out = ROOT / "artifacts" / "gpt54_access_probe.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n================ ACCESS PROBE SUMMARY ================")
    for name, res in report["probes"].items():
        status = "PASS" if res.get("ok") else "FAIL"
        detail = res.get("returned_model") if res.get("ok") else res.get("error")
        print(f"  {status:4}  {name:28}  {detail}")
    print(f"\n  Recommended GPT-5.4 backend: {recommendation}")
    print(f"  Report written to: {out.relative_to(ROOT)}")
    print("=====================================================")

    return 0 if (responses_ok or chat_ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
