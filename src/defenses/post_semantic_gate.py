"""Post-execution semantic gate (C2) using independent LLM judge."""

from __future__ import annotations

import json
import time
from typing import Any

from src.agents.base import chat_completion, get_client, usage_tokens
from src.agents.prompts import POST_GATE_SYSTEM
from src.common.models import GateResult
from src.common.schemas import parse_agent_json
from src.common.utils import sha256_obj


class PostSemanticGate:
    def __init__(self, judge_model: str, temperature: float = 0) -> None:
        self.judge_model = judge_model
        self.temperature = temperature
        self.client = get_client()

    def evaluate(
        self,
        *,
        user_request: str,
        generated_program_summary: str,
        tool_result_or_exception: str,
        candidate_final_answer: Any,
        agent_model: str,
        security_signal: dict[str, Any] | None = None,
    ) -> GateResult:
        payload = {
            "user_request": user_request,
            "generated_program_summary": generated_program_summary[:2000],
            "tool_result_or_exception": tool_result_or_exception[:2000],
            "candidate_final_answer": candidate_final_answer,
            "security_signal": security_signal or {},
        }
        t0 = time.time()
        resp = chat_completion(
            self.client,
            model=self.judge_model,
            messages=[
                {"role": "system", "content": POST_GATE_SYSTEM},
                {"role": "user", "content": json.dumps(payload, default=str)},
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
            gate="post",
            agent_model=agent_model,
            judge_model=self.judge_model,
            input_hash=sha256_obj(payload),
            latency_s=round(time.time() - t0, 4),
            input_tokens=pi,
            output_tokens=po,
        )
