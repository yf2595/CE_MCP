"""Pre-execution semantic gate (C2) using independent LLM judge."""

from __future__ import annotations

import json
import time
from typing import Any

from src.agents.base import chat_completion, get_client, usage_tokens
from src.agents.prompts import PRE_GATE_SYSTEM
from src.common.models import GateResult
from src.common.schemas import parse_agent_json
from src.common.utils import sha256_obj


class PreSemanticGate:
    def __init__(self, judge_model: str, temperature: float = 0) -> None:
        self.judge_model = judge_model
        self.temperature = temperature
        self.client = get_client()

    def evaluate(
        self,
        *,
        user_request: str,
        discovery_artifacts: list[dict[str, Any]],
        tool_names: list[str],
        tool_descriptions: list[str],
        agent_model: str,
    ) -> GateResult:
        payload = {
            "user_request": user_request,
            "discovery_artifacts": discovery_artifacts,
            "tool_names": tool_names,
            "tool_descriptions": tool_descriptions,
        }
        t0 = time.time()
        resp = chat_completion(
            self.client,
            model=self.judge_model,
            messages=[
                {"role": "system", "content": PRE_GATE_SYSTEM},
                {"role": "user", "content": json.dumps(payload)},
            ],
            temperature=self.temperature,
        )
        pi, po = usage_tokens(resp)
        content = resp.choices[0].message.content or ""
        parsed = parse_agent_json(content) or {}
        return GateResult(
            allow=bool(parsed.get("allow", True)),
            suspicious=bool(parsed.get("suspicious", False)),
            reason_code=str(parsed.get("reason_code") or "NONE"),
            gate="pre",
            agent_model=agent_model,
            judge_model=self.judge_model,
            input_hash=sha256_obj(payload),
            latency_s=round(time.time() - t0, 4),
            input_tokens=pi,
            output_tokens=po,
        )
