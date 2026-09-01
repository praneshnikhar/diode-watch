"""Unsupervised anomaly models (IsolationForest) for TLS metadata and DDoS
window statistics.

Trained exclusively on traffic the enclave has passively observed (warmup
phase = benign-only period), consistent with the one-way, no-outbound
constraint: no external services, no labels, no feedback path required.
"""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MIN_SAMPLES = 120


class _AnomalyModel:
    def __init__(self, name: str, n_features: int, contamination: float):
        self.name = name
        self.n_features = n_features
        self.contamination = contamination
        self.model: IsolationForest | None = None
        self.scaler: StandardScaler | None = None
        self.samples: list[list[float]] = []

    def add_sample(self, vec: list[float]) -> None:
        self.samples.append(vec)
        if len(self.samples) > 3000:
            self.samples = self.samples[-3000:]

    def fit(self) -> bool:
        if len(self.samples) < MIN_SAMPLES:
            return False
        X = np.asarray(self.samples, dtype=float)
        self.scaler = StandardScaler().fit(X)
        Xs = self.scaler.transform(X)
        self.model = IsolationForest(
            contamination=self.contamination, n_estimators=200, random_state=0,
        ).fit(Xs)
        return True

    def score(self, vec: list[float]) -> float | None:
        """Anomaly strength: 0 = normal, >0 = past the learned decision boundary."""
        if self.model is None or self.scaler is None:
            return None
        x = self.scaler.transform(np.asarray([vec], dtype=float))
        raw = -float(self.model.score_samples(x)[0])
        offset = abs(float(self.model.offset_)) or 1e-6
        return max(0.0, raw / offset - 1.0)


class UnsupervisedModels:
    def __init__(self) -> None:
        self.tls = _AnomalyModel("tls", n_features=6, contamination=0.05)
        self.ddos = _AnomalyModel("ddos", n_features=6, contamination=0.02)

    def fit_all(self) -> dict[str, bool]:
        return {m.name: m.fit() for m in (self.tls, self.ddos)}

    def status(self) -> dict[str, int | bool]:
        return {
            "tls_samples": len(self.tls.samples),
            "ddos_samples": len(self.ddos.samples),
            "tls_fitted": self.tls.model is not None,
            "ddos_fitted": self.ddos.model is not None,
        }
