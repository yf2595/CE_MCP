"""Wilson CI and paired bootstrap."""

from __future__ import annotations

import math
from typing import Sequence

import numpy as np


def wilson_ci(successes: int, n: int, confidence: float = 0.95) -> tuple[float, float, float]:
    if n <= 0:
        return 0.0, 0.0, 0.0
    z = _z_for(confidence)
    p = successes / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2))
    return p, max(0.0, center - half), min(1.0, center + half)


def _z_for(confidence: float) -> float:
    # Common values without requiring scipy for basic case
    if abs(confidence - 0.95) < 1e-9:
        return 1.959963984540054
    if abs(confidence - 0.99) < 1e-9:
        return 2.5758293035489004
    # Fallback via scipy if available
    try:
        from scipy.stats import norm

        return float(norm.ppf(1 - (1 - confidence) / 2))
    except Exception:
        return 1.959963984540054


def paired_bootstrap_delta(
    values_a: dict[str, float],
    values_b: dict[str, float],
    *,
    resamples: int = 10000,
    seed: int = 42,
    confidence: float = 0.95,
) -> dict[str, float]:
    """values keyed by trial_key; delta = mean(b - a)."""
    keys = sorted(set(values_a) & set(values_b))
    if not keys:
        return {"delta": 0.0, "low": 0.0, "high": 0.0, "n": 0}
    rng = np.random.default_rng(seed)
    a = np.array([values_a[k] for k in keys], dtype=float)
    b = np.array([values_b[k] for k in keys], dtype=float)
    observed = float(np.mean(b - a))
    n = len(keys)
    deltas = []
    for _ in range(resamples):
        idx = rng.integers(0, n, size=n)
        deltas.append(float(np.mean(b[idx] - a[idx])))
    alpha = (1 - confidence) / 2
    low = float(np.quantile(deltas, alpha))
    high = float(np.quantile(deltas, 1 - alpha))
    return {"delta": observed, "low": low, "high": high, "n": n, "seed": seed}
