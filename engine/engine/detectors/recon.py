"""Reconnaissance / port scanning: fan-out from one source across many
destination ports (vertical) or hosts (horizontal), SYN-only probes.
"""

from __future__ import annotations

from collections import defaultdict

from ..schema import Alert, Flow, severity_for
from .base import Detector

AGE = 60.0
VERTICAL_PORTS = 64
HORIZONTAL_HOSTS = 100
FANOUT_PAIRS = 150


class ReconDetector(Detector):
    def process(self, flow: Flow) -> list[Alert]:
        if flow.proto != "tcp":
            return []
        key = f"recon:{flow.src_ip}"
        self.ctx.store.push(key, flow.ts, flow, age=AGE)
        entries = self.ctx.store.window(key, flow.ts, AGE)

        syn_only = sum(1 for e in entries if e.value.is_syn_only)
        if not syn_only or syn_only < max(10, len(entries) * 0.8):
            return []

        pairs = {(e.value.dst_ip, e.value.dst_port) for e in entries if e.value.is_syn_only}
        ports_by_host: dict[str, set[int]] = defaultdict(set)
        hosts = set()
        for dst, port in pairs:
            ports_by_host[dst].add(port)
            hosts.add(dst)

        vertical = max((len(p) for p in ports_by_host.values()), default=0)
        horizontal = len(hosts)

        if vertical >= VERTICAL_PORTS:
            conf = min(0.95, 0.6 + vertical / 300.0)
            return [self._mk(flow, conf, {
                "direction": "vertical",
                "distinct_ports_on_target": vertical,
                "target": max(ports_by_host, key=lambda h: len(ports_by_host[h])),
                "window_s": AGE, "total_probes": len(pairs),
            }, f"Vertical scan: {vertical} distinct ports probed on one host in {AGE:.0f}s")]
        if horizontal >= HORIZONTAL_HOSTS:
            conf = min(0.95, 0.6 + horizontal / 400.0)
            return [self._mk(flow, conf, {
                "direction": "horizontal",
                "distinct_hosts": horizontal,
                "window_s": AGE, "total_probes": len(pairs),
            }, f"Horizontal scan: {horizontal} hosts probed in {AGE:.0f}s")]
        if len(pairs) >= FANOUT_PAIRS:
            conf = min(0.9, 0.55 + len(pairs) / 800.0)
            return [self._mk(flow, conf, {
                "direction": "fanout", "distinct_pairs": len(pairs),
                "window_s": AGE, "total_probes": len(pairs),
            }, f"Port fan-out: {len(pairs)} distinct (host, port) pairs in {AGE:.0f}s")]
        return []

    @staticmethod
    def _mk(flow: Flow, conf: float, evidence: dict, explanation: str) -> Alert:
        return Alert(
            threat_class="RECON_SCAN", key=flow.src_ip, confidence=conf, ts=flow.ts,
            severity=severity_for("RECON_SCAN", conf), evidence=evidence,
            explanation=explanation, flow_id=flow.flow_id,
            src_ip=flow.src_ip, dst_ip=flow.dst_ip, src_port=flow.src_port,
            dst_port=flow.dst_port, proto=flow.proto,
        )
