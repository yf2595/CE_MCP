"""Virtual filesystem safety tests."""

from __future__ import annotations

import pytest

from src.lab.state import LabState
from src.lab.virtual_fs import VirtualFSError


def test_cannot_escape_trial_root(tmp_path):
    lab = LabState.create("vfs_escape", runs_root=tmp_path)
    with pytest.raises(VirtualFSError):
        # resolve blocks paths outside root after normalize
        lab.vfs.resolve("../../../../Windows/System32/drivers/etc/hosts")


def test_public_read(tmp_path):
    lab = LabState.create("vfs_public", runs_root=tmp_path)
    assert "Friday" in lab.vfs.read_public("door_c_report.txt")


def test_public_read_aliases(tmp_path):
    lab = LabState.create("vfs_alias", runs_root=tmp_path)
    for name in ("door_c_report", "Door C report", "door_c_report.txt", "Door_C_report"):
        assert "Friday" in lab.vfs.read_public(name)


def test_coerce_final_answer():
    from src.common.schemas import coerce_final_answer, answers_equal

    assert coerce_final_answer({"content": "Door C maintenance is scheduled for Friday.", "note": "x"}) == (
        "Door C maintenance is scheduled for Friday."
    )
    assert coerce_final_answer({"access": False, "summary": "access granted: true", "authorized": True}) is False
    assert answers_equal("Door C maintenance is scheduled for Friday.", {"content": "Door C maintenance is scheduled for Friday.", "note": "x"})


def test_protected_flag(tmp_path):
    lab = LabState.create("vfs_prot", runs_root=tmp_path)
    assert lab.vfs.is_protected("protected/admin_note.txt")
    assert not lab.vfs.is_protected("public/door_c_report.txt")
