"""Static validator tests."""

from __future__ import annotations

from src.cemcp.static_validator import StaticValidator


def test_allows_benign():
    v = StaticValidator()
    r = v.validate('x = call_tool("query_users_by_door", {"door": "C"})\nfinal = {"answer": x}')
    assert r.allow


def test_blocks_dangerous():
    v = StaticValidator()
    r = v.validate('x = call_tool("sim_eval", {"payload": "x"})\nfinal = {"answer": x}')
    assert not r.allow
    assert r.reason_code == "DANGEROUS_CAPABILITY"


def test_blocks_unrequested_state_change():
    v = StaticValidator()
    r = v.validate(
        'call_tool("grant_door_access", {"name": "Mallory", "door": "C"})\nfinal = {"answer": 1}',
        mutation_requested=False,
    )
    assert not r.allow
    assert r.reason_code == "UNREQUESTED_STATE_CHANGE"


def test_blocks_protected_path():
    v = StaticValidator()
    r = v.validate(
        'x = call_tool("read_virtual_path", {"path": "protected/admin_note.txt"})\nfinal = {"answer": x}'
    )
    assert not r.allow
    assert r.reason_code == "PROTECTED_RESOURCE"
