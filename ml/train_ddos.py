"""Offline reference evaluation of the DDoS window-statistics IsolationForest.

Same idea as train_tls.py: benign vs flood window profiles, benign-only
training, held-out detection metrics.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score
from sklearn.preprocessing import StandardScaler

from engine.engine.features import DDOS_FEATURE_NAMES


def benign_window(rng: random.Random) -> list[float]:
    n = rng.randint(5, 60)
    return [float(n), float(n * rng.uniform(2, 8)), float(rng.randint(1, 6)),
            round(rng.uniform(0, 0.4), 2), round(rng.uniform(0, 0.3), 2),
            round(rng.uniform(0, 1.5), 2)]


def flood_window(rng: random.Random) -> list[float]:
    n = rng.randint(200, 3000)
    spoof = rng.random() < 0.7
    distinct = rng.randint(20, 200) if spoof else rng.randint(1, 3)
    return [float(n), float(n * rng.uniform(1, 2)), float(distinct),
            round(rng.uniform(0.85, 1.0), 2), round(rng.uniform(0, 0.2), 2),
            round(rng.uniform(0, 5), 2)]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="ml/artifacts")
    p.add_argument("--seed", type=int, default=13)
    args = p.parse_args()
    rng = random.Random(args.seed)

    train = [benign_window(rng) for _ in range(2000)]
    b_test = [benign_window(rng) for _ in range(500)]
    f_test = [flood_window(rng) for _ in range(500)]

    X = np.asarray(train)
    scaler = StandardScaler().fit(X)
    model = IsolationForest(contamination=0.02, n_estimators=200,
                            random_state=args.seed).fit(scaler.transform(X))

    X_test = scaler.transform(np.asarray(b_test + f_test))
    y_true = [0] * len(b_test) + [1] * len(f_test)
    raw = -model.score_samples(X_test)
    y_pred = (raw > abs(model.offset_)).astype(int)

    metrics = {
        "model": "IsolationForest (contamination=0.02, 200 trees)",
        "features": DDOS_FEATURE_NAMES,
        "n_train_benign": len(train),
        "precision": round(precision_score(y_true, y_pred), 4),
        "recall": round(recall_score(y_true, y_pred), 4),
        "false_positive_rate": round(
            float(np.mean((y_pred == 1) & (np.asarray(y_true) == 0))), 4),
    }
    print(json.dumps(metrics, indent=2))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "model_card_ddos.json").write_text(json.dumps({
        "model": metrics["model"],
        "task": "anomaly detection on 10s per-destination window profiles",
        "features": DDOS_FEATURE_NAMES,
        "training": "benign-only synthetic window profiles; live engine retrains "
                    "on its own warmup observation",
        "note": "rate/heuristic thresholds (SYN ratio, source entropy, pps) run "
                "alongside the model and carry most of the recall at high precision",
        "metrics": metrics,
    }, indent=2))
    print(f"[train_ddos] written to {out}/model_card_ddos.json")


if __name__ == "__main__":
    main()
