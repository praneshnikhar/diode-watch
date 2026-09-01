"""DGA domains + DNS tunnelling from query names only (no payload access).

DGA: LightGBM classifier (entropy, length, n-gram anomaly, digit/vowel ratios,
label count, TLD, hex-lookalike) with heuristic fallback.
Tunnelling: high-entropy, long labels, TXT/NULL record preference.
"""

from __future__ import annotations

from ..features import dga_features, shannon_entropy
from ..schema import Alert, Flow, severity_for
from .base import Detector

DGA_THRESHOLD = 0.65


class DgaDnsDetector(Detector):
    def process(self, flow: Flow) -> list[Alert]:
        if not flow.dns or not flow.dns.get("qname"):
            return []
        qname = str(flow.dns["qname"]).rstrip(".").lower()
        if len(qname) > 253:
            return []
        qtype = str(flow.dns.get("qtype", "A")).upper()

        # drift sampling (PSI baseline vs recent window)
        self.ctx.sample_dga_entropy(shannon_entropy(qname.split(".")[0]))

        # -- tunnelling first (long, high-entropy names) ----------------------
        ent = shannon_entropy(qname)
        length = len(qname)
        tunnelish = (ent >= 3.6 and length >= 40) or (ent >= 4.3 and length >= 25)
        if tunnelish:
            conf = min(0.9, 0.65 + 0.15 * (ent - 3.6) + (0.08 if qtype in ("TXT", "NULL") else 0.0))
            return [self._alert(flow, "DNS_TUNNEL", flow.src_ip, conf, qname, qtype, ent, length, None)]
        if ent >= 4.6 and qtype in ("TXT", "NULL") and length >= 20:
            return [self._alert(flow, "DNS_TUNNEL", flow.src_ip, 0.7, qname, qtype, ent, length, None)]

        # -- DGA classification ----------------------------------------------
        prob, source = self.ctx.dga.predict(qname)
        if prob >= DGA_THRESHOLD:
            return [self._alert(flow, "DGA_DOMAIN", flow.src_ip, min(prob, 0.95),
                                qname, qtype, ent, length, {"prob": prob, "method": source})]
        return []

    @staticmethod
    def _alert(flow: Flow, cls: str, key: str, conf: float, qname: str,
               qtype: str, ent: float, length: int, extra: dict | None) -> Alert:
        f = dga_features(qname)
        evidence = {
            "domain": qname, "entropy": round(ent, 3), "length": length,
            "qtype": qtype, "ngram_anomaly": round(f["ngram_anomaly"], 3),
        }
        if extra:
            evidence.update(extra)
        explanation = (
            f"DNS query '{qname}' (entropy {ent:.2f}, {length} chars, {qtype}) "
            f"matches {'DGA-generated' if cls == 'DGA_DOMAIN' else 'tunnelled'} profile"
        )
        return Alert(
            threat_class=cls, key=key, confidence=conf, ts=flow.ts,
            severity=severity_for(cls, conf), evidence=evidence,
            explanation=explanation, flow_id=flow.flow_id,
            src_ip=flow.src_ip, dst_ip=flow.dst_ip, src_port=flow.src_port,
            dst_port=flow.dst_port, proto=flow.proto,
        )
