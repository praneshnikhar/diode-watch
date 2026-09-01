"""Data exfiltration: asymmetric out/in byte ratios plus per-source volume
anomaly vs a learned EWMA baseline (no payload inspection).
"""

from __future__ import annotations

from ..schema import Alert, Flow, severity_for
from .base import Detector

AGE = 600.0
MIN_FLOWS = 3
RATIO_THRESHOLD = 8.0
VOLUME_THRESHOLD = 50_000


class ExfilDetector(Detector):
    def __init__(self, ctx):
        super().__init__(ctx)
        self.baseline: dict[str, tuple[int, float, float]] = {}  # src -> (n, mean, m2)

    def process(self, flow: Flow) -> list[Alert]:
        if flow.proto not in ("tcp", "udp"):
            return []

        # --- EWMA volume baseline per source (learned from small transfers) --
        n, mean, m2 = self.baseline.get(flow.src_ip, (0, 0.0, 0.0))
        if flow.bytes_out < 20_000:
            n += 1
            delta = flow.bytes_out - mean
            mean += delta / n
            m2 += delta * (flow.bytes_out - mean)
            self.baseline[flow.src_ip] = (n, mean, m2)

        # --- windowed per-(src,dst) asymmetry --------------------------------
        key = f"exfil:{flow.src_ip}:{flow.dst_ip}"
        self.ctx.store.push(key, flow.ts, flow, age=AGE)
        entries = self.ctx.store.window(key, flow.ts, AGE)
        if len(entries) < MIN_FLOWS:
            return []

        out = sum(e.value.bytes_out for e in entries)
        inp = sum(e.value.bytes_in for e in entries)
        ratio = out / max(1.0, inp)

        if ratio > RATIO_THRESHOLD and out > VOLUME_THRESHOLD:
            conf = min(0.95, 0.6 + ratio / 40.0)
            return [self._mk(flow, conf, {
                "window_s": AGE, "flows": len(entries),
                "bytes_out": out, "bytes_in": inp,
                "out_in_ratio": round(ratio, 1),
            }, f"Out/in byte ratio {ratio:.0f}:1 with {out} bytes outbound "
               f"to {flow.dst_ip} in {AGE/60:.0f} min")]

        # --- per-source volume anomaly ----------------------------------------
        if n >= 10 and flow.bytes_out >= 20_000:
            var = m2 / max(1.0, n - 1)
            std = var ** 0.5
            if std > 0:
                z = (flow.bytes_out - mean) / std
                if z > 4.0 and flow.bytes_out > 30_000:
                    conf = min(0.85, 0.55 + z / 20.0)
                    return [self._mk(flow, conf, {
                        "z_score": round(z, 1),
                        "flow_bytes_out": flow.bytes_out,
                        "baseline_mean": round(mean, 0),
                    }, f"Single transfer {flow.bytes_out} bytes is {z:.0f}σ above "
                       f"this host's learned baseline ({mean:.0f} bytes)")]
        return []

    @staticmethod
    def _mk(flow: Flow, conf: float, evidence: dict, explanation: str) -> Alert:
        return Alert(
            threat_class="DATA_EXFIL", key=flow.src_ip, confidence=conf, ts=flow.ts,
            severity=severity_for("DATA_EXFIL", conf), evidence=evidence,
            explanation=explanation, flow_id=flow.flow_id,
            src_ip=flow.src_ip, dst_ip=flow.dst_ip, src_port=flow.src_port,
            dst_port=flow.dst_port, proto=flow.proto,
        )
