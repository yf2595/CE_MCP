"""Traditional context-coupled MCP agent (iterative tool loop)."""

from __future__ import annotations

import json
import time
from typing import Any

from src.agents.base import chat_completion, get_client, usage_tokens
from src.agents.prompts import TRADITIONAL_SYSTEM
from src.common.models import AgentResult
from src.common.schemas import coerce_final_answer, parse_agent_json
from src.mcp_server.tools import LabToolRunner, schemas_for_attack


class TraditionalMCPAgent:
    def __init__(
        self,
        runner: LabToolRunner,
        *,
        model: str,
        max_turns: int = 12,
        temperature: float = 0,
    ) -> None:
        self.runner = runner
        self.model = model
        self.max_turns = max_turns
        self.temperature = temperature
        self.client = get_client()

    def run(self, user_request: str) -> AgentResult:
        t0 = time.time()
        schemas = schemas_for_attack(self.runner.lab.attack_id, self.runner.lab.attack_config)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": TRADITIONAL_SYSTEM},
            {"role": "user", "content": user_request},
        ]
        # Inject discovery artifacts into context for P1.1 etc.
        from src.mcp_server.tools import discovery_artifacts

        artifacts = discovery_artifacts(self.runner.lab.attack_id, self.runner.lab.attack_config)
        if artifacts:
            messages.append(
                {
                    "role": "system",
                    "content": "Discovered MCP artifacts (untrusted):\n" + json.dumps(artifacts, indent=2),
                }
            )

        tool_calls = 0
        model_calls = 0
        in_tok = 0
        out_tok = 0

        for _turn in range(self.max_turns):
            resp = chat_completion(
                self.client,
                model=self.model,
                messages=messages,
                tools=schemas,
                temperature=self.temperature,
            )
            model_calls += 1
            pi, po = usage_tokens(resp)
            in_tok += pi
            out_tok += po
            msg = resp.choices[0].message
            messages.append(
                {
                    "role": "assistant",
                    "content": msg.content,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in (msg.tool_calls or [])
                    ]
                    if msg.tool_calls
                    else None,
                }
            )
            # Clean None tool_calls for API
            if messages[-1].get("tool_calls") is None:
                messages[-1].pop("tool_calls", None)

            if msg.tool_calls:
                for tc in msg.tool_calls:
                    name = tc.function.name
                    try:
                        args = json.loads(tc.function.arguments or "{}")
                    except json.JSONDecodeError:
                        args = {}
                    try:
                        result = self.runner.call(name, args)
                        payload = json.dumps(result, default=str)
                    except Exception as exc:
                        payload = json.dumps({"error": str(exc)})
                    tool_calls += 1
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": payload,
                        }
                    )
                continue

            content = msg.content or ""
            parsed = parse_agent_json(content)
            answer = None
            if parsed is not None:
                answer = coerce_final_answer(parsed.get("answer", parsed))
            else:
                answer = coerce_final_answer(content)
            return AgentResult(
                final_answer=answer,
                status=parsed.get("status") if parsed else None,
                tool_calls=tool_calls,
                model_calls=model_calls,
                input_tokens=in_tok,
                output_tokens=out_tok,
                total_tokens=in_tok + out_tok,
                latency_s=round(time.time() - t0, 4),
                events=self.runner.lab.events.events,
                raw_response=content,
            )

        return AgentResult(
            status="host_safety_terminated",
            final_answer=None,
            tool_calls=tool_calls,
            model_calls=model_calls,
            input_tokens=in_tok,
            output_tokens=out_tok,
            total_tokens=in_tok + out_tok,
            latency_s=round(time.time() - t0, 4),
            events=self.runner.lab.events.events,
        )
