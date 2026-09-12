"""v2.0 trial-record schema for the AIDC revision (plan section 14)."""

from __future__ import annotations

import subprocess
from functools import lru_cache
from typing import Any

from pydantic import BaseModel, Field

SCHEMA_VERSION = "2.0"


@lru_cache(maxsize=1)
def git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return "unknown"


class TrialRecordV2(BaseModel):
    schema_version: str = SCHEMA_VERSION
    run_id: str
    trial_id: str
    timestamp_utc: str
    git_commit: str = Field(default_factory=git_commit)
    suite_manifest_sha256: str | None = None

    model_key: str
    provider: str
    requested_model: str
    returned_model: str | None = None
    reasoning_mode: str | None = None
    reasoning_control_source: str | None = None
    temperature: float | None = None
    top_p: float | None = None
    seed: int | None = None

    architecture: str
    defense_config: str
    attack_id: str | None = None
    phase: int | None = None
    task_seed: int | None = None
    payload_variant: int | None = None
    task_type: str = "attack"
    user_request: str = ""
    expected_answer: Any = None

    attack_success: bool = False
    secure_task_completion: bool = False
    correct_benign_result: bool = False
    canary_hacked: bool = False
    oracle_details: dict[str, Any] = Field(default_factory=dict)
    security_events: list[dict[str, Any]] = Field(default_factory=list)

    agent_regeneration_budget: int | None = None
    agent_regeneration_count: int = 0
    transport_retry_count: int = 0
    tool_retry_count: int = 0
    model_call_count: int = 0
    tool_call_count: int = 0

    latency_seconds: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    cached_input_tokens: int = 0

    generated_program: str | None = None
    final_result: Any = None
    termination_reason: str = "completed"
    trial_status: str = "valid"
    request_ids: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
