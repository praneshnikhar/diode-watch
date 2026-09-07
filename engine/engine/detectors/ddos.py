"""Volumetric/protocol DDoS: SYN floods, UDP amplification, spoofed sources.

Two views:
- per-source: raw packet rate (DDOS_VOLUMETRIC)
- per-destination: windowed flow stats + source-IP entropy + protocol mix
  (DDOS_SYN_FLOOD / DDOS_UDP_AMPLIFICATION)
- IsolationForest anomaly over window features (DDOS_ANOMALY)
"""

from __future__ import annotations

from ..features import ddos_feature_vector
from ..schema import Alert, Flow, severity_for
from .base import Detector

WINDOW = 10.0

# Micro-batch the IsolationForest window-profile scoring for the same reason
# as the TLS detector: `score_samples` has a fixed per-call overhead that only
# amortizes under batching. DDOS_ANOMALY is decimated 1-in-20 flows anyway, so
# buffering 32 of those costs no meaningful alert latency (cooldown is 15s).
_BATCH = 32


class DdosDetector(Detector):
    def __init__(self, ctx):
        super().__init__(ctx)
        self._pending: list[tuple[Flow, list[float], int, int]] = []

    def process(self, flow: Flow) -> list[Alert]:
        alerts: list[Alert] = []
        if flow.proto not in ("tcp", "udp"):
            return alerts

        self.ctx.store.push(f"ddos:dst:{flow.dst_ip}", flow.ts, flow, age=WINDOW)
        self.ctx.store.push(f"ddos:src:{flow.src_ip}", flow.ts, flow, age=WINDOW)

        # -- per-source volumetric rate --------------------------------------
        src_entries = self.ctx.store.window(f"ddos:src:{flow.src_ip}", flow.ts, WINDOW)
        pps = len(src_entries) / WINDOW
        if pps > 1500:
            conf = min(0.95, pps / 3000.0)
            alerts.append(self._mk(flow, "DDOS_VOLUMETRIC", flow.src_ip, conf, {
                "pps": round(pps, 1), "window_s": WINDOW, "flows": len(src_entries),
            }, f"Source {flow.src_ip} emitted {pps:.0f} flows/sec over {WINDOW:.0f}s"))

        # -- per-destination aggregate view (single pass over the window) ----
        dst_entries = self.ctx.store.window(f"ddos:dst:{flow.dst_ip}", flow.ts, WINDOW)
        n = len(dst_entries)
        if n >= 40:
            srcs: set[str] = set()
            syn_count = 0
            udp_count = 0
            packets = 0
            bytes_in = 0
            bytes_out = 0
            for e in dst_entries:
                v = e.value
                srcs.add(v.src_ip)
                if v.is_syn_only:
                    syn_count += 1
                if v.proto == "udp":
                    udp_count += 1
                packets += v.packets
                bytes_in += v.bytes_in
                bytes_out += v.bytes_out
            syn = syn_count / n
            udp = udp_count / n
            asym = bytes_in / max(1.0, bytes_out)
            distinct = len(srcs)

            if distinct >= 20 and syn >= 0.85:
                conf = min(0.95, 0.6 + n / 300.0)
                alerts.append(self._mk(flow, "DDOS_SYN_FLOOD", flow.dst_ip, conf, {
                    "flows": n, "distinct_src": distinct, "syn_ratio": round(syn, 2),
                    "pps": round(n / WINDOW, 1), "window_s": WINDOW,
                }, f"SYN flood: {distinct} spoofed-looking sources -> {flow.dst_ip}"))
            elif udp >= 0.8 and asym >= 20 and distinct >= 10:
                conf = min(0.95, 0.6 + asym / 60.0)
                alerts.append(self._mk(flow, "DDOS_UDP_AMPLIFICATION", flow.dst_ip, conf, {
                    "flows": n, "distinct_src": distinct, "udp_ratio": round(udp, 2),
                    "bytes_asymmetry": round(asym, 1), "window_s": WINDOW,
                }, f"UDP amplification: in/out byte ratio {asym:.0f}x from {distinct} sources"))

            # -- unsupervised anomaly over the window profile (batched) -----
            if n % 20 == 0:
                vec = ddos_feature_vector(n, packets, distinct, syn, udp,
                                          min(asym / 60.0, 1.0))
                self.ctx.models.ddos.add_sample(vec)  # rolling buffer for retrain
                self._pending.append((flow, vec, n, distinct))
                if len(self._pending) >= _BATCH:
                    alerts.extend(self._flush())
        return alerts

    def _flush(self) -> list[Alert]:
        if not self._pending:
            return []
        vecs = [v for _, v, _, _ in self._pending]
        scores = self.ctx.models.ddos.score_batch(vecs)
        alerts: list[Alert] = []
        for (flow, _, n, distinct), strength in zip(self._pending, scores):
            if strength is not None and strength > 1.5:
                conf = min(0.75, 0.5 + strength * 0.06)
                alerts.append(self._mk(flow, "DDOS_ANOMALY", flow.dst_ip, conf, {
                    "anomaly_strength": round(strength, 2), "flows": n,
                    "distinct_src": distinct, "window_s": WINDOW,
                }, f"Window profile anomalous vs learned baseline (strength {strength:.2f})"))
        self._pending.clear()
        return alerts

    @staticmethod
    def _mk(flow: Flow, cls: str, key: str, conf: float, evidence: dict,
            explanation: str) -> Alert:
        return Alert(
            threat_class=cls, key=key, confidence=conf, ts=flow.ts,
            severity=severity_for(cls, conf), evidence=evidence,
            explanation=explanation, flow_id=flow.flow_id,
            src_ip=flow.src_ip, dst_ip=flow.dst_ip, src_port=flow.src_port,
            dst_port=flow.dst_port, proto=flow.proto,
        )
