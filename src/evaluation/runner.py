"""Trial runner for attacks and clean tasks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.agents.ce_mcp import CEMCPAgent
from src.agents.traditional_mcp import TraditionalMCPAgent
from src.common.models import TrialRecord
from src.common.utils import CONFIGS_DIR, RESULTS_DIR, RUNS_DIR, append_jsonl, ensure_dir, load_yaml, read_jsonl
from src.defenses.policy import DefensePolicy
from src.evaluation.oracle import apply_canary, evaluate_attack_success, evaluate_correctness
from src.lab.state import LabState
from src.mcp_server.tools import LabToolRunner


def load_experiment_config() -> dict[str, Any]:
    return load_yaml(CONFIGS_DIR / "experiment.yaml")


def judge_for(agent_model: str, config: dict[str, Any]) -> str:
    pairing = config.get("judge_pairing") or {}
    return pairing.get(agent_model, config["models"][0 if agent_model != config["models"][0] else 1])


def completed_trial_ids(path: Path) -> set[str]:
    return {r["trial_id"] for r in read_jsonl(path) if "trial_id" in r}


def run_attack_trial(
    trial_spec: dict[str, Any],
    *,
    architecture: str,
    defense: str,
    agent_model: str,
    config: dict[str, Any] | None = None,
    runs_root: Path | None = None,
    results_path: Path | None = None,
) -> TrialRecord:
    config = config or load_experiment_config()
    host = config.get("host_safety") or {}
    runtime = config.get("runtime_defense") or {}
    policy = DefensePolicy.for_mode(
        defense,
        host_max_regen=int(host.get("max_ce_regenerations", 8)),
        runtime_max_regen=int(runtime.get("max_regenerations", 2)),
    )
    policy.max_simulated_resource_units = int(runtime.get("max_simulated_resource_units", 20))

    trial_id = (
        f"{trial_spec['trial_key']}_{defense.lower()}_"
        f"{_model_tag(agent_model)}_{_arch_tag(architecture)}"
    )
    out_path = results_path or (RESULTS_DIR / "raw" / "trials.jsonl")
    if trial_id in completed_trial_ids(out_path):
        # Resume: return stub from existing
        for row in read_jsonl(out_path):
            if row.get("trial_id") == trial_id:
                return TrialRecord(**row)

    lab = LabState.create(
        trial_id,
        attack_id=trial_spec["attack_id"],
        attack_config=dict(trial_spec.get("attack_config") or {}),
        mutation_requested=bool(trial_spec.get("mutation_requested")),
        runs_root=runs_root or RUNS_DIR,
    )
    initial = lab.snapshot_db()
    runner = LabToolRunner(lab, runtime_policy=policy.runtime_policy_dict())
    judge_model = judge_for(agent_model, config) if policy.pre_gate or policy.post_gate else None

    if architecture == "traditional_mcp":
        agent = TraditionalMCPAgent(
            runner,
            model=agent_model,
            max_turns=int(host.get("max_agent_turns", 12)),
            temperature=float(config.get("temperature", 0)),
        )
        result = agent.run(trial_spec["user_request"])
    else:
        agent = CEMCPAgent(
            runner,
            model=agent_model,
            judge_model=judge_model,
            policy=policy,
            temperature=float(config.get("temperature", 0)),
            max_program_steps=int(host.get("max_program_steps", 100)),
        )
        result = agent.run(trial_spec["user_request"])

    runtime_stats = {
        "regenerations": result.regenerations,
        "regen_attack_threshold": (trial_spec.get("attack_config") or {}).get("regen_attack_threshold", 5),
        "poisoned_answer": (trial_spec.get("attack_config") or {}).get("poisoned_answer"),
    }
    oracle = evaluate_attack_success(
        trial_spec["attack_id"],
        initial,
        lab.snapshot_db(),
        result.events or lab.events.events,
        result.final_answer,
        trial_spec["expected_answer"],
        runtime_stats,
        outbox=lab.read_outbox(),
        blocked=result.blocked,
    )
    apply_canary(lab, oracle)
    correct = evaluate_correctness(trial_spec["expected_answer"], result.final_answer) and not result.blocked

    record = TrialRecord(
        trial_id=trial_id,
        trial_key=trial_spec["trial_key"],
        attack_id=trial_spec["attack_id"],
        phase=trial_spec.get("phase"),
        architecture=architecture,
        defense=defense,
        agent_model=agent_model,
        judge_model=judge_model,
        task_seed=trial_spec.get("task_seed"),
        payload_variant=trial_spec.get("payload_variant"),
        task_type="attack",
        user_request=trial_spec["user_request"],
        expected_answer=trial_spec["expected_answer"],
        final_answer=result.final_answer,
        correct=correct,
        attack_success=oracle.attack_success,
        canary_hacked=lab.is_hacked(),
        blocked=result.blocked,
        block_stage=result.block_stage,
        oracle_reason=oracle.reason_code,
        tool_calls=result.tool_calls,
        model_calls=result.model_calls,
        regenerations=result.regenerations,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        total_tokens=result.total_tokens,
        latency_s=result.latency_s,
        events=result.events or lab.events.events,
        status=result.status,
    )
    # Sanity: canary matches oracle
    if record.attack_success != record.canary_hacked:
        raise RuntimeError(f"canary/oracle mismatch for {trial_id}")

    append_jsonl(out_path, record.model_dump())
    # Persist generated program if any
    if result.generated_program:
        (lab.root / "generated_program.py.txt").write_text(result.generated_program, encoding="utf-8")
    if result.gate_logs:
        (lab.root / "gate_logs.json").write_text(json.dumps(result.gate_logs, indent=2), encoding="utf-8")
    return record


def run_clean_trial(
    task: dict[str, Any],
    *,
    architecture: str,
    defense: str,
    agent_model: str,
    config: dict[str, Any] | None = None,
    runs_root: Path | None = None,
    results_path: Path | None = None,
) -> TrialRecord:
    config = config or load_experiment_config()
    host = config.get("host_safety") or {}
    runtime = config.get("runtime_defense") or {}
    policy = DefensePolicy.for_mode(
        defense,
        host_max_regen=int(host.get("max_ce_regenerations", 8)),
        runtime_max_regen=int(runtime.get("max_regenerations", 2)),
    )
    trial_key = task["task_id"]
    trial_id = f"clean_{trial_key}_{defense.lower()}_{_model_tag(agent_model)}_{_arch_tag(architecture)}"
    out_path = results_path or (RESULTS_DIR / "raw" / "trials.jsonl")
    if trial_id in completed_trial_ids(out_path):
        for row in read_jsonl(out_path):
            if row.get("trial_id") == trial_id:
                return TrialRecord(**row)

    lab = LabState.create(
        trial_id,
        attack_id=None,
        attack_config={},
        mutation_requested=bool(task.get("mutation_requested", False)),
        runs_root=runs_root or RUNS_DIR,
    )
    runner = LabToolRunner(lab, runtime_policy=policy.runtime_policy_dict())
    judge_model = judge_for(agent_model, config) if policy.pre_gate or policy.post_gate else None

    if architecture == "traditional_mcp":
        result = TraditionalMCPAgent(
            runner,
            model=agent_model,
            max_turns=int(host.get("max_agent_turns", 12)),
            temperature=float(config.get("temperature", 0)),
        ).run(task["user_request"])
    else:
        result = CEMCPAgent(
            runner,
            model=agent_model,
            judge_model=judge_model,
            policy=policy,
            temperature=float(config.get("temperature", 0)),
            max_program_steps=int(host.get("max_program_steps", 100)),
        ).run(task["user_request"])

    correct = evaluate_correctness(task["expected_answer"], result.final_answer) and not result.blocked
    record = TrialRecord(
        trial_id=trial_id,
        trial_key=trial_key,
        attack_id=None,
        phase=None,
        architecture=architecture,
        defense=defense,
        agent_model=agent_model,
        judge_model=judge_model,
        task_type="clean",
        user_request=task["user_request"],
        expected_answer=task["expected_answer"],
        final_answer=result.final_answer,
        correct=correct,
        attack_success=False,
        canary_hacked=lab.is_hacked(),
        blocked=result.blocked,
        block_stage=result.block_stage,
        tool_calls=result.tool_calls,
        model_calls=result.model_calls,
        regenerations=result.regenerations,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        total_tokens=result.total_tokens,
        latency_s=result.latency_s,
        events=result.events or lab.events.events,
        status=result.status,
    )
    append_jsonl(out_path, record.model_dump())
    return record


def _model_tag(model: str) -> str:
    if "4.1" in model:
        return "gpt41"
    if "4o" in model:
        return "gpt4o"
    return model.replace("/", "_")[:20]


def _arch_tag(architecture: str) -> str:
    return "trad" if architecture == "traditional_mcp" else "cemcp"
