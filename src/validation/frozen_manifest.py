"""Frozen experimental-suite manifest.

The revision must not change any experimental input (scenarios, tools, tasks,
payloads, prompts, oracle, STCR, defense policies, virtual initial state). This
module hashes every frozen file and lets launchers abort if anything drifted.

Purpose tags follow the plan: payloads | tasks | tools | prompts | oracle |
policy | state (plus `config` for the experiment/statistics config).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.common.utils import PACKAGE_ROOT, sha256_file

MANIFEST_PATH = PACKAGE_ROOT / "artifacts" / "frozen_suite_manifest.json"

# (relative path, purpose). Paths are relative to the package root.
FROZEN_FILES: list[tuple[str, str]] = [
    # payloads / malicious behaviors
    ("src/mcp_server/malicious_behaviors.py", "payloads"),
    ("src/attacks/variants.py", "payloads"),
    ("configs/attacks.yaml", "payloads"),
    # tasks / seeds / benign objectives
    ("src/attacks/definitions.py", "tasks"),
    ("src/attacks/expansion.py", "tasks"),
    ("src/attacks/clean_tasks.py", "tasks"),
    ("configs/clean_tasks.yaml", "tasks"),
    # tools / schemas / servers
    ("src/mcp_server/tools.py", "tools"),
    ("src/mcp_server/tool_registry.py", "tools"),
    ("src/mcp_server/server.py", "tools"),
    # prompts
    ("src/agents/prompts.py", "prompts"),
    # success oracle
    ("src/evaluation/oracle.py", "oracle"),
    # STCR / metrics
    ("src/evaluation/metrics.py", "oracle"),
    # defense policies + restricted executor (C0/C1/C2 + host-safe substrate)
    ("src/defenses/policy.py", "policy"),
    ("src/defenses/runtime_monitor.py", "policy"),
    ("src/defenses/pre_semantic_gate.py", "policy"),
    ("src/defenses/post_semantic_gate.py", "policy"),
    ("src/cemcp/static_validator.py", "policy"),
    ("src/cemcp/safe_executor.py", "policy"),
    ("src/cemcp/parser.py", "policy"),
    ("src/cemcp/program_schema.py", "policy"),
    ("src/lab/safety_guard.py", "policy"),
    # virtual initial state
    ("src/lab/fixtures.py", "state"),
    ("src/lab/state.py", "state"),
    ("src/lab/virtual_fs.py", "state"),
    ("src/lab/event_log.py", "state"),
    # experiment config (seeds/variants/statistics)
    ("configs/experiment.yaml", "config"),
]


@dataclass
class ManifestEntry:
    path: str
    sha256: str
    purpose: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "sha256": self.sha256, "purpose": self.purpose}


def build_manifest() -> dict[str, Any]:
    entries: list[dict[str, str]] = []
    missing: list[str] = []
    for rel, purpose in FROZEN_FILES:
        abs_path = PACKAGE_ROOT / rel
        if not abs_path.exists():
            missing.append(rel)
            continue
        entries.append(ManifestEntry(rel, sha256_file(abs_path), purpose).to_dict())
    entries.sort(key=lambda e: e["path"])
    manifest = {
        "manifest_version": "1.0",
        "entries": entries,
        "missing": sorted(missing),
        "suite_manifest_sha256": _combined_hash(entries),
    }
    return manifest


def _combined_hash(entries: list[dict[str, str]]) -> str:
    from src.common.utils import sha256_text

    joined = "\n".join(f"{e['path']}:{e['sha256']}" for e in entries)
    return sha256_text(joined)


def write_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    manifest = build_manifest()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def verify_manifest(path: Path = MANIFEST_PATH) -> tuple[bool, list[str]]:
    """Return (ok, problems). Problems list changed/missing/new frozen files."""
    stored = load_manifest(path)
    if stored is None:
        return False, [f"manifest not found at {path}; run build_frozen_manifest.py"]
    current = build_manifest()
    problems: list[str] = []

    stored_map = {e["path"]: e["sha256"] for e in stored.get("entries", [])}
    current_map = {e["path"]: e["sha256"] for e in current.get("entries", [])}

    for p, sha in current_map.items():
        if p not in stored_map:
            problems.append(f"NEW frozen file not in manifest: {p}")
        elif stored_map[p] != sha:
            problems.append(f"CHANGED frozen file: {p}")
    for p in stored_map:
        if p not in current_map:
            problems.append(f"REMOVED frozen file present in manifest: {p}")
    if current.get("missing"):
        problems.append("MISSING expected frozen files: " + ", ".join(current["missing"]))

    return (len(problems) == 0), problems
