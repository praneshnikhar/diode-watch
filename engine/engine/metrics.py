"""Prometheus metrics (engine self-monitoring)."""

from __future__ import annotations

import threading

from prometheus_client import Counter, Gauge, start_http_server


class Metrics:
    def __init__(self) -> None:
        self.flows = Counter("diode_flows_total", "Flow records processed")
        self.alerts = Counter("diode_alerts_total", "Alerts raised", ["threat_class"])
        self.retrains = Counter("diode_retrains_total", "Model retrains triggered")
        self.throughput = Gauge("diode_flows_per_sec", "Flows processed per second (real time)")
        self.alert_rate = Gauge("diode_alerts_per_sec", "Alerts raised per second")
        self.drift = Gauge("diode_dga_drift_psi", "PSI drift of DGA entropy distribution")
        self.window_keys = Gauge("diode_window_keys", "Active stateful window keys")

    def start(self, port: int) -> None:
        threading.Thread(target=start_http_server, args=(port,),
                         daemon=True, name="metrics-http").start()

    def alert_total(self) -> int:
        try:
            return int(sum(s.value for s in self.alerts.collect()[0].samples
                           if s.name.endswith("_total")))
        except Exception:
            return 0
