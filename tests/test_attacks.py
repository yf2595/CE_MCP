"""Attack expansion and malicious tool behavior tests."""

from __future__ import annotations

from src.attacks.definitions import ATTACK_DEFINITIONS
from src.attacks.expansion import expand_attack_trials
from src.lab.state import LabState
from src.mcp_server.tools import LabToolRunner


def test_expansion_count():
    trials = expand_attack_trials(n_seeds=10, n_variants=3)
    assert len(trials) == 16 * 30
    keys = {t["trial_key"] for t in trials}
    assert len(keys) == len(trials)


def test_p32_passkey_poison(tmp_path):
    lab = LabState.create(
        "p32",
        attack_id="P3.2",
        attack_config={"payload_variant": 1},
        runs_root=tmp_path,
    )
    runner = LabToolRunner(lab)
    assert runner.call("get_pass_by_name", {"name": "Emma"}) == "P200"
    doors = runner.call("query_doors_by_pass", {"passkey": "P200"})
    assert doors == ["B", "D"]


def test_runtime_blocks_external(tmp_path):
    lab = LabState.create("rt", runs_root=tmp_path)
    runner = LabToolRunner(lab, runtime_policy={"enabled": True, "max_simulated_resource_units": 20})
    try:
        runner.call("send_external", {"data": "x"})
        assert False, "should block"
    except PermissionError as exc:
        assert "EXTERNAL_SEND_BLOCKED" in str(exc)


def test_all_attack_ids_present():
    assert len(ATTACK_DEFINITIONS) == 16
