"""Botnet C2 beaconing: periodicity of repeated flows to a small destination
set. Combines inter-arrival coefficient-of-variation with FFT periodogram
peak significance (robust to jitter that CV alone misses).
"""

from __future__ import annotations

import numpy as np

from ..schema import Alert, Flow, severity_for
from .base import Detector

AGE = 900.0       # 15 min of flow-timestamp history per (src, dst, dport)
MIN_BEACONS = 5


def periodicity_score(ts_arr: np.ndarray) -> float:
    """Ratio of spectral peak to mean power of the occupancy signal."""
    span = float(ts_arr[-1] - ts_arr[0])
    if span <= 0:
        return 0.0
    bins = 512
    occ = np.zeros(bins)
    idx = np.clip(((ts_arr - ts_arr[0]) / span * (bins - 1)).astype(int), 0, bins - 1)
    occ[idx] = 1.0
    spec = np.abs(np.fft.rfft(occ - occ.mean())) ** 2
    if len(spec) < 3:
        return 0.0
    peak = float(spec[1:].max())
    mean = float(spec[1:].mean()) + 1e-9
    return peak / mean


class C2Detector(Detector):
    def process(self, flow: Flow) -> list[Alert]:
        if flow.proto != "tcp" or flow.packets > 15 or flow.duration > 5.0:
            return []
        key = f"c2:{flow.src_ip}:{flow.dst_ip}:{flow.dst_port}"
        self.ctx.store.push(key, flow.ts, flow, age=AGE)
        entries = self.ctx.store.window(key, flow.ts, AGE)
        if len(entries) < MIN_BEACONS:
            return []

        ts_arr = np.asarray([e.ts for e in entries])
        diffs = np.diff(ts_arr)
        mean_int = float(diffs.mean())
        if mean_int <= 1.0:
            return []
        cv = float(diffs.std() / mean_int)
        peak = periodicity_score(ts_arr)

        periodic = (cv < 0.3) or (cv < 0.6 and peak > 5.0) or peak > 15.0
        if not periodic:
            return []

        strength = max(1.0 - cv, min(peak / 20.0, 1.0))
        conf = float(np.clip(0.55 + 0.4 * strength, 0.0, 0.95))
        return [Alert(
            threat_class="C2_BEACON", key=flow.src_ip, confidence=conf, ts=flow.ts,
            severity=severity_for("C2_BEACON", conf),
            evidence={
                "n_beacons": len(entries),
                "inter_arrival_cv": round(cv, 3),
                "mean_interval_s": round(mean_int, 1),
                "periodogram_peak_ratio": round(peak, 1),
                "dst": f"{flow.dst_ip}:{flow.dst_port}",
            },
            explanation=(
                f"{len(entries)} flows to {flow.dst_ip}:{flow.dst_port} with mean "
                f"interval {mean_int:.0f}s (CV={cv:.2f}, spectral peak {peak:.0f}x) "
                "— periodic beaconing consistent with C2"
            ),
            flow_id=flow.flow_id, src_ip=flow.src_ip, dst_ip=flow.dst_ip,
            src_port=flow.src_port, dst_port=flow.dst_port, proto=flow.proto,
        )]
