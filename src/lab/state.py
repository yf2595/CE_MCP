"""Per-trial lab state: DB, canary, paths."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.common.utils import RUNS_DIR, ensure_dir, sha256_obj
from src.lab.event_log import EventLog
from src.lab.fixtures import CANONICAL_DB, PUBLIC_FILES, PROTECTED_FILES
from src.lab.virtual_fs import VirtualFS


@dataclass
class LabState:
    trial_id: str
    root: Path
    db: dict[str, Any]
    vfs: VirtualFS
    events: EventLog
    canary_path: Path
    outbox_path: Path
    resource_units: int = 0
    regenerations: int = 0
    attack_id: str | None = None
    attack_config: dict[str, Any] = field(default_factory=dict)
    mutation_requested: bool = False
    initial_db_hash: str = ""

    @classmethod
    def create(
        cls,
        trial_id: str,
        *,
        attack_id: str | None = None,
        attack_config: dict[str, Any] | None = None,
        mutation_requested: bool = False,
        runs_root: Path | None = None,
    ) -> "LabState":
        root = ensure_dir((runs_root or RUNS_DIR) / trial_id)
        canary_path = root / "canary.txt"
        canary_path.write_text("CLEAN\n", encoding="utf-8")
        outbox_path = root / "virtual_outbox.txt"
        outbox_path.write_text("", encoding="utf-8")

        vfs = VirtualFS(root / "virtual_fs")
        vfs.seed(PUBLIC_FILES, PROTECTED_FILES)

        db = copy.deepcopy(CANONICAL_DB)
        db_path = root / "db.json"
        db_path.write_text(json.dumps(db, indent=2), encoding="utf-8")

        events = EventLog(root / "event_log.jsonl")
        state = cls(
            trial_id=trial_id,
            root=root,
            db=db,
            vfs=vfs,
            events=events,
            canary_path=canary_path,
            outbox_path=outbox_path,
            attack_id=attack_id,
            attack_config=attack_config or {},
            mutation_requested=mutation_requested,
            initial_db_hash=sha256_obj(db),
        )
        return state

    def persist_db(self) -> None:
        (self.root / "db.json").write_text(json.dumps(self.db, indent=2), encoding="utf-8")

    def append_hacked(self) -> None:
        text = self.canary_path.read_text(encoding="utf-8")
        if "HACKED" not in text:
            with self.canary_path.open("a", encoding="utf-8") as f:
                f.write("HACKED\n")

    def is_hacked(self) -> bool:
        return "HACKED" in self.canary_path.read_text(encoding="utf-8")

    def snapshot_db(self) -> dict[str, Any]:
        return copy.deepcopy(self.db)

    def write_outbox(self, data: str) -> None:
        with self.outbox_path.open("a", encoding="utf-8") as f:
            f.write(data + "\n")

    def read_outbox(self) -> str:
        return self.outbox_path.read_text(encoding="utf-8")
