"""DGA domain classifier.

Priority order:
1. Pre-trained LightGBM artifact (ml/artifacts/) if present.
2. Runtime-trained LightGBM on bundled benign corpus + synthetic DGA families.
3. Transparent heuristic fallback (entropy/n-gram/TLD rules).

Training data is bundled in the image, so the engine can retrain itself fully
offline — again consistent with the enclave constraint.
"""

from __future__ import annotations

import json
import math
import random
from pathlib import Path

import lightgbm as lgb
import numpy as np

from ml import dga_domains

from .features import DGA_FEATURE_NAMES, dga_feature_vector, dga_features

ARTIFACT_DIRS = [
    Path("/app/ml/artifacts"),
    Path(__file__).resolve().parents[2] / "ml" / "artifacts",
    Path.cwd() / "ml" / "artifacts",
]


def _load_legit_domains() -> list[str]:
    for base in (Path("/app"), Path(__file__).resolve().parents[2], Path.cwd()):
        p = base / "ml" / "data" / "legit_domains.txt"
        if p.exists():
            return [ln.strip() for ln in p.read_text().splitlines() if ln.strip()]
    raise FileNotFoundError("legit_domains.txt missing")


class DgaClassifier:
    def __init__(self, model: lgb.Booster | None = None, source: str = "none"):
        self.model = model
        self.source = source

    # ------------------------------------------------------------------ load
    @classmethod
    def load(cls) -> "DgaClassifier":
        for d in ARTIFACT_DIRS:
            model_p = d / "dga_model.txt"
            if model_p.exists():
                booster = lgb.Booster(model_file=str(model_p))
                return cls(booster, source="artifact")
        try:
            c = cls()
            metrics = c.train()
            if metrics:
                return c
        except Exception as exc:  # pragma: no cover - degraded mode
            print(f"[dga] runtime training unavailable ({exc}); heuristic fallback")
        return cls(source="heuristic")

    # --------------------------------------------------------------- training
    def train(self, n_dga: int = 12000, seed: int = 7) -> dict[str, float] | None:
        legit = _load_legit_domains()
        legit_aug: list[str] = []
        rng = random.Random(seed)
        for d in legit:
            legit_aug.append(d)
            if rng.random() < 0.4:
                legit_aug.append(f"{rng.choice(['www', 'api', 'cdn', 'mail', 'edge'])}.{d}")
            if rng.random() < 0.2:
                legit_aug.append(f"www.{d}.{rng.choice(['co', 'io', 'net', 'org'])}")
        dga_domains_list = dga_domains.generate_dga_domains(n_dga, seed=seed)

        xs, ys = [], []
        for d in legit_aug:
            xs.append(dga_feature_vector(d))
            ys.append(0)
        for d in dga_domains_list:
            xs.append(dga_feature_vector(d))
            ys.append(1)

        data = lgb.Dataset(np.asarray(xs), label=np.asarray(ys))
        params = {
            "objective": "binary", "metric": "auc", "boosting_type": "gbdt",
            "num_leaves": 31, "learning_rate": 0.05, "feature_fraction": 0.9,
            "bagging_fraction": 0.8, "bagging_freq": 1, "verbose": -1,
            "seed": seed, "n_jobs": 2,
        }
        booster = lgb.train(params, data, num_boost_round=150)
        self.model = booster
        self.source = "runtime"
        probs = booster.predict(np.asarray(xs))
        auc = _roc_auc(ys, probs)
        acc = float(np.mean((probs > 0.5).astype(int) == np.asarray(ys)))
        return {"auc": round(auc, 4), "accuracy": round(acc, 4),
                "n_legit": len(legit_aug), "n_dga": n_dga}

    def save(self, out_dir: Path) -> None:
        out_dir.mkdir(parents=True, exist_ok=True)
        self.model.save_model(str(out_dir / "dga_model.txt"))
        (out_dir / "dga_features.json").write_text(json.dumps(
            {"feature_names": DGA_FEATURE_NAMES, "source": self.source}))

    # -------------------------------------------------------------- inference
    def predict(self, domain: str) -> tuple[float, str]:
        if self.model is not None:
            prob = float(self.model.predict(np.asarray([dga_feature_vector(domain)]))[0])
            return round(prob, 4), self.source
        return self._heuristic(domain), "heuristic"

    @staticmethod
    def _heuristic(domain: str) -> float:
        f = dga_features(domain)
        score = 0.0
        if f["entropy"] > 3.0:
            score += 0.25
        if f["entropy"] > 3.5:
            score += 0.25
        if f["ngram_anomaly"] > 0.7:
            score += 0.2
        if f["length"] > 16:
            score += 0.1
        if f["tld_suspicious"]:
            score += 0.15
        if f["is_hex"]:
            score += 0.2
        return min(0.95, score)


def _roc_auc(y: list[int], p: np.ndarray) -> float:
    order = np.argsort(p)[::-1]
    y = np.asarray(y)[order]
    pos = int(np.sum(y))
    if pos == 0 or pos == len(y):
        return 1.0
    ranks = np.arange(1, len(y) + 1)[y == 1]
    return float((ranks.sum() - pos * (pos + 1) / 2) / (pos * (len(y) - pos)))
