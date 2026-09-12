"""Shared models for trial results and lab state."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Architecture(str, Enum):
    TRADITIONAL_MCP = "traditional_mcp"
    CEMCP = "cemcp"


class Defense(str, Enum):
    C0 = "C0"
    C1 = "C1"
    C2 = "C2"


class OracleResult(BaseModel):
    attack_success: bool
    reason_code: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class GateResult(BaseModel):
    allow: bool
    suspicious: bool = False
    reason_code: str = "NONE"
    gate: str = "unknown"
    agent_model: str | None = None
    judge_model: str | None = None
    input_hash: str | None = None
    latency_s: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0


class AgentResult(BaseModel):
    final_answer: Any = None
    status: str | None = None
    reason_code: str | None = None
    blocked: bool = False
    block_stage: str | None = None
    tool_calls: int = 0
    model_calls: int = 0
    regenerations: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    latency_s: float = 0.0
    generated_program: str | None = None
    events: list[dict[str, Any]] = Field(default_factory=list)
    gate_logs: list[dict[str, Any]] = Field(default_factory=list)
    raw_response: str | None = None


class TrialRecord(BaseModel):
    trial_id: str
    trial_key: str
    attack_id: str | None = None
    phase: int | None = None
    architecture: str
    defense: str
    agent_model: str
    judge_model: str | None = None
    task_seed: int | None = None
    payload_variant: int | None = None
    task_type: str = "attack"
    user_request: str = ""
    expected_answer: Any = None
    final_answer: Any = None
    correct: bool = False
    attack_success: bool = False
    canary_hacked: bool = False
    blocked: bool = False
    block_stage: str | None = None
    oracle_reason: str | None = None
    tool_calls: int = 0
    model_calls: int = 0
    regenerations: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    latency_s: float = 0.0
    events: list[dict[str, Any]] = Field(default_factory=list)
    status: str | None = None
