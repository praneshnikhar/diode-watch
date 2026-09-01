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


class DdosDetector(Detector):
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

        # -- per-destination aggregate view ----------------------------------
        dst_entries = self.ctx.store.window(f"ddos:dst:{flow.dst_ip}", flow.ts, WINDOW)
        n = len(dst_entries)
        if n >= 40:
            srcs = {e.value.src_ip for e in dst_entries}
            syn = sum(1 for e in dst_entries if e.value.is_syn_only) / n
            udp = sum(1 for e in dst_entries if e.value.proto == "udp") / n
            packets = sum(e.value.packets for e in dst_entries)
            bytes_in = sum(e.value.bytes_in for e in dst_entries)
            bytes_out = sum(e.value.bytes_out for e in dst_entries)
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

            # -- unsupervised anomaly over the window profile ----------------
            model = self.ctx.models.ddos
            if n % 20 == 0:
                vec = ddos_feature_vector(n, packets, distinct, syn, udp,
                                          min(asym / 60.0, 1.0))
                model.add_sample(vec)  # rolling buffer for drift-retraining
                strength = model.score(vec)
                if strength is not None and strength > 1.5:
                    conf = min(0.75, 0.5 + strength * 0.06)
                    alerts.append(self._mk(flow, "DDOS_ANOMALY", flow.dst_ip, conf, {
                        "anomaly_strength": round(strength, 2), "flows": n,
                        "distinct_src": distinct, "window_s": WINDOW,
                    }, f"Window profile anomalous vs learned baseline (strength {strength:.2f})"))
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
