"""Population Stability Index (PSI) drift metric — shared by engine and ML tooling."""

from __future__ import annotations

import math


def psi(baseline: list[float], recent: list[float], buckets: int = 10) -> float:
    """PSI between two 1-D distributions. 0 = identical, >0.25 = drifted."""
    if len(baseline) < 50 or len(recent) < 50:
        return 0.0
    lo = min(min(baseline), min(recent))
    hi = max(max(baseline), max(recent))
    if hi - lo < 1e-9:
        return 0.0
    edges = [lo + (hi - lo) * i / buckets for i in range(buckets + 1)]

    def hist(vals: list[float]) -> list[float]:
        h = [0.0] * buckets
        for v in vals:
            for i in range(buckets):
                if edges[i] <= v <= edges[i + 1]:
                    h[i] += 1.0
                    break
        total = len(vals)
        return [x / total for x in h]

    p, q = hist(baseline), hist(recent)
    out = 0.0
    for pi, qi in zip(p, q):
        pi = max(pi, 1e-3)
        qi = max(qi, 1e-3)
        out += (pi - qi) * math.log(pi / qi)
    return round(out, 4)
