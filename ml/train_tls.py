"""Offline reference evaluation of the TLS-metadata IsolationForest detector.

Generates synthetic benign/malware TLS session metadata (same feature space
the engine uses), fits IsolationForest on benign-only data, and reports
detection rates on a held-out mix. The live engine retrains the same model
from its own passively observed warmup traffic; this script documents the
offline reference behaviour.
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

from engine.engine.features import TLS_FEATURE_NAMES


def benign_sample(rng: random.Random) -> list[float]:
    return [
        rng.randint(280, 420),          # client hello size
        rng.randint(90, 220),           # server hello size
        rng.choice([1, 2, 2, 3]),       # cert depth
        rng.randint(6, 12),             # handshake packets
        round(rng.uniform(2.8, 4.2), 2),  # cipher entropy
        round(rng.uniform(0.3, 0.8), 2),  # packet size ratio
    ]


def malware_sample(rng: random.Random) -> list[float]:
    return [
        rng.randint(480, 700),
        rng.randint(80, 110),
        1,
        rng.randint(8, 14),
        round(rng.uniform(1.2, 2.4), 2),
        round(rng.uniform(0.6, 1.0), 2),
    ]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="ml/artifacts")
    p.add_argument("--seed", type=int, default=11)
    args = p.parse_args()
    rng = random.Random(args.seed)

    train = [benign_sample(rng) for _ in range(1500)]
    benign_test = [benign_sample(rng) for _ in range(500)]
    malware_test = [malware_sample(rng) for _ in range(500)]

    X = np.asarray(train)
    scaler = StandardScaler().fit(X)
    model = IsolationForest(contamination=0.05, n_estimators=200,
                            random_state=args.seed).fit(scaler.transform(X))

    X_test = scaler.transform(np.asarray(benign_test + malware_test))
    y_true = [0] * len(benign_test) + [1] * len(malware_test)
    raw = -model.score_samples(X_test)
    threshold = abs(model.offset_)
    y_pred = (raw > threshold).astype(int)

    metrics = {
        "model": "IsolationForest (contamination=0.05, 200 trees)",
        "features": TLS_FEATURE_NAMES,
        "n_train_benign": len(train),
        "n_test_benign": len(benign_test),
        "n_test_malware": len(malware_test),
        "precision": round(precision_score(y_true, y_pred), 4),
        "recall": round(recall_score(y_true, y_pred), 4),
        "false_positive_rate": round(
            float(np.mean((y_pred == 1) & (np.asarray(y_true) == 0))), 4),
    }
    print(json.dumps(metrics, indent=2))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "model_card_tls.json").write_text(json.dumps({
        "model": metrics["model"],
        "task": "anomaly detection on TLS session metadata (no decryption)",
        "features": TLS_FEATURE_NAMES,
        "training": "benign-only synthetic TLS metadata; live engine retrains on "
                    "its own warmup observation",
        "metrics": metrics,
        "limitations": [
            "Reference evaluation uses synthetic metadata distributions; "
            "real-world client heterogeneity raises false-positive risk.",
            "JA3 denylist provides an independent high-precision signal.",
        ],
    }, indent=2))
    print(f"[train_tls] written to {out}/model_card_tls.json")


if __name__ == "__main__":
    main()
