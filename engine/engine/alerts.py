"""Alert manager: severity mapping, session dedup/cooldown, fan-out to
DB queue, Redis pub/sub (dashboard) and n8n webhook (orchestration).
"""

from __future__ import annotations

import asyncio
import json
import urllib.request
from collections import defaultdict

from .config import Config
from .schema import Alert, Flow, severity_for

# seconds (flow timestamps) of silence before an alert session resets
COOLDOWN: dict[str, float] = {
    "DDOS_SYN_FLOOD": 15, "DDOS_UDP_AMPLIFICATION": 15, "DDOS_VOLUMETRIC": 15,
    "DDOS_ANOMALY": 15, "C2_BEACON": 45, "DGA_DOMAIN": 20, "DNS_TUNNEL": 20,
    "TLS_MALWARE": 30, "RECON_SCAN": 30, "DATA_EXFIL": 30,
}
SESSION_GAP = 300.0


class AlertManager:
    def __init__(self, cfg: Config, db_queue, redis, metrics):
        self.cfg = cfg
        self.db_queue = db_queue
        self.redis = redis
        self.metrics = metrics
        self._last_fire: dict[tuple[str, str], float] = {}
        self._sessions: dict[tuple[str, str], tuple[str, int, float]] = {}

    def submit(self, alert: Alert) -> None:
        key = (alert.threat_class, alert.key)
        now = alert.ts
        last = self._last_fire.get(key, float("-inf"))
        if now - last < COOLDOWN.get(alert.threat_class, 15):
            return
        self._last_fire[key] = now

        sess = self._sessions.get(key)
        if sess and now - sess[2] < SESSION_GAP:
            alert.alert_id, count, _ = sess
            alert.occurrences = count + 1
            self._sessions[key] = (alert.alert_id, alert.occurrences, now)
        else:
            self._sessions[key] = (alert.alert_id, 1, now)

        payload = json.dumps(alert.to_dict())
        self.db_queue.put(alert.to_dict())
        self.metrics.alerts.labels(alert.threat_class).inc()
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._publish(payload, alert))
        except RuntimeError:
            pass  # no running event loop (unit tests)

    async def _publish(self, payload: str, alert: Alert) -> None:
        try:
            await self.redis.publish("diode:alerts", payload)
        except Exception as exc:  # pragma: no cover
            print(f"[alerts] redis publish failed: {exc}")
        if (alert.severity in ("CRITICAL", "HIGH") and self.cfg.n8n_webhook_url):
            await asyncio.to_thread(self._post_n8n, payload)

    def _post_n8n(self, payload: str) -> None:
        try:
            req = urllib.request.Request(
                self.cfg.n8n_webhook_url, data=payload.encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=3)
        except Exception:
            pass  # n8n is best-effort; never block the detection path
