"""Engine context: shared state, drift monitoring, retraining."""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass, field

from ml.drift import psi as _psi

from .alerts import AlertManager
from .config import Config
from .dga_model import DgaClassifier
from .models import UnsupervisedModels
from .windows import WindowStore

DRIFT_THRESHOLD = 0.25


@dataclass
class Context:
    cfg: Config
    store: WindowStore
    models: UnsupervisedModels
    dga: DgaClassifier
    manager: AlertManager
    redis: object
    metrics: object
    dga_samples: deque[float] = field(default_factory=lambda: deque(maxlen=2000))
    dga_baseline: list[float] = field(default_factory=list)
    baseline_locked: bool = False
    last_drift: float = 0.0
    sim_ts: float = 0.0  # current simulation time (latest flow ts), for dashboards

    def sample_dga_entropy(self, entropy: float) -> None:
        self.dga_samples.append(entropy)
        if not self.baseline_locked and len(self.dga_samples) >= 800:
            self.dga_baseline = list(self.dga_samples)
            self.baseline_locked = True

    async def retrain(self, model: str = "all") -> dict:
        results: dict = {}
        if model in ("dga", "all"):
            try:
                metrics = self.dga.train()
                results["dga"] = {"ok": True, "metrics": metrics}
            except Exception as exc:
                results["dga"] = {"ok": False, "error": str(exc)}
        if model in ("tls", "ddos", "all"):
            fitted = self.models.fit_all()
            results.update({k: {"ok": v} for k, v in fitted.items()})
        self.metrics.retrains.inc()
        payload = json.dumps({"event": "retrain", "model": model, "results": results})
        await self.redis.publish("diode:events", payload)
        return results

    def compute_drift(self) -> dict:
        if not self.baseline_locked:
            return {"drift": 0.0, "reason": "baseline not locked yet"}
        psi = _psi(self.dga_baseline, list(self.dga_samples)[-800:])
        self.last_drift = psi
        self.metrics.drift.set(psi)
        return {"drift": psi, "threshold": DRIFT_THRESHOLD,
                "alarmed": psi > DRIFT_THRESHOLD}
