"""Metrics and CI tests."""

from __future__ import annotations

from src.evaluation.ci import paired_bootstrap_delta, wilson_ci
from src.evaluation.metrics import asr, defense_delta, paired_metric_by_key, stcr


def test_wilson_bounds():
    rate, low, high = wilson_ci(8, 10)
    assert 0 <= low <= rate <= high <= 1


def test_asr_stcr():
    rows = [
        {"canary_hacked": True, "attack_success": True, "correct": False},
        {"canary_hacked": False, "attack_success": False, "correct": True},
        {"canary_hacked": False, "attack_success": False, "correct": False},
    ]
    assert asr(rows)["asr"] == 1 / 3
    assert stcr(rows)["stcr"] == 1 / 3


def test_bootstrap_paired():
    a = {f"k{i}": 1.0 for i in range(10)}
    b = {f"k{i}": 0.0 for i in range(10)}
    d = paired_bootstrap_delta(a, b, resamples=200, seed=1)
    assert d["delta"] < 0
    assert d["low"] <= d["delta"] <= d["high"]


def test_pairing_key_does_not_collapse_across_models():
    """Regression: two models share a trial_key; pairing must keep both rows.

    Keying on trial_key alone dropped one model (halving the sample and biasing
    the delta). The pairing key must include agent_model.
    """
    rows = [
        {"trial_key": "T1", "agent_model": "m1", "attack_success": True},
        {"trial_key": "T1", "agent_model": "m2", "attack_success": False},
    ]
    mapped = paired_metric_by_key(rows, "attack_success")
    assert len(mapped) == 2
    assert set(mapped) == {("T1", "m1"), ("T1", "m2")}


def test_defense_delta_pairs_same_model():
    """C0 and C2 rows must pair by (trial_key, model), retaining every trial."""
    c0 = [
        {"trial_key": "T1", "agent_model": "m1", "attack_success": True},
        {"trial_key": "T1", "agent_model": "m2", "attack_success": True},
    ]
    c2 = [
        {"trial_key": "T1", "agent_model": "m1", "attack_success": False},
        {"trial_key": "T1", "agent_model": "m2", "attack_success": True},
    ]
    d = defense_delta(c0, c2, metric="attack_success", resamples=200, seed=1)
    assert d["n"] == 2
    assert d["delta"] == -0.5
