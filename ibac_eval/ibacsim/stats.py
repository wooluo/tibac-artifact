"""Statistics: bootstrap CIs, paired bootstrap tests, aggregation helpers."""
from __future__ import annotations

import random
from typing import Sequence

import numpy as np


def boot_ci(vals: Sequence[float], b: int = 2000, seed: int = 7,
            stat=np.mean) -> tuple:
    """Percentile bootstrap CI for `stat` over vals."""
    arr = np.asarray([v for v in vals if v == v], dtype=float)  # drop NaN
    if len(arr) == 0:
        return float("nan"), float("nan"), float("nan")
    rng = random.Random(seed)
    n = len(arr)
    stats = np.empty(b)
    for i in range(b):
        idx = [rng.randrange(n) for _ in range(n)]
        stats[i] = stat(arr[idx])
    point = float(stat(arr))
    return point, float(np.percentile(stats, 2.5)), float(np.percentile(stats, 97.5))


def paired_boot(x: Sequence[float], y: Sequence[float], b: int = 4000,
                seed: int = 7) -> dict:
    """Paired bootstrap for mean(x) - mean(y).

    x and y must be positionally aligned; pairs where either side is NaN are
    dropped as whole pairs (never independently, which would misalign).
    """
    pairs = [(vx, vy) for vx, vy in zip(x, y) if vx == vx and vy == vy]
    if not pairs:
        return {"diff": float("nan"), "ci": (float("nan"), float("nan")),
                "p": float("nan"), "n": 0}
    xa = np.asarray([p[0] for p in pairs], dtype=float)
    ya = np.asarray([p[1] for p in pairs], dtype=float)
    n = len(pairs)
    diffs = xa - ya
    rng = random.Random(seed)
    means = np.empty(b)
    for i in range(b):
        idx = [rng.randrange(n) for _ in range(n)]
        means[i] = np.mean(diffs[idx])
    diff = float(np.mean(diffs))
    lo, hi = float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))
    # two-sided p: probability the resampled diff crosses zero
    cross = np.mean(means <= 0) if diff > 0 else np.mean(means >= 0)
    p = min(1.0, 2.0 * float(cross))
    p = max(p, 1.0 / b)
    return {"diff": diff, "ci": (lo, hi), "p": p, "n": int(n)}


def fmt_ci(point: float, lo: float, hi: float, pct: bool = True) -> str:
    if point != point:
        return "n/a"
    scale = 100 if pct else 1
    return f"{point * scale:.1f}% [{lo * scale:.1f}, {hi * scale:.1f}]"


def fmt_p(p: float) -> str:
    if p != p:
        return "n/a"
    return "<1e-4" if p < 1e-4 else f"{p:.4f}"
