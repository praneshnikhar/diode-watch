"""Offline DGA classifier training with held-out evaluation, feature
importance and (optional) SHAP analysis. Writes artifacts + model card.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

import numpy as np
from lightgbm import LGBMClassifier
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split

from engine.engine.dga_model import _load_legit_domains
from engine.engine.features import DGA_FEATURE_NAMES, dga_feature_vector
from ml import dga_domains


def build_dataset(n_dga: int = 12000, seed: int = 7) -> tuple[np.ndarray, np.ndarray]:
    rng = random.Random(seed)
    legit = _load_legit_domains()
    legit_aug = []
    for d in legit:
        legit_aug.append(d)
        if rng.random() < 0.4:
            legit_aug.append(f"{rng.choice(['www', 'api', 'cdn', 'mail', 'edge'])}.{d}")
        if rng.random() < 0.2:
            legit_aug.append(f"www.{d}.{rng.choice(['co', 'io', 'net', 'org'])}")
    dgas = dga_domains.generate_dga_domains(n_dga, seed=seed)
    xs = [dga_feature_vector(d) for d in legit_aug] + [dga_feature_vector(d) for d in dgas]
    ys = [0] * len(legit_aug) + [1] * len(dgas)
    return np.asarray(xs), np.asarray(ys)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="ml/artifacts")
    p.add_argument("--n-dga", type=int, default=12000)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--no-shap", action="store_true")
    args = p.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    print("[train_dga] building dataset...")
    X, y = build_dataset(args.n_dga, args.seed)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=args.seed)

    print(f"[train_dga] train={len(X_tr)} test={len(X_te)}")
    model = LGBMClassifier(
        n_estimators=150, learning_rate=0.05, num_leaves=31,
        subsample=0.8, colsample_bytree=0.9, random_state=args.seed, verbose=-1)
    model.fit(X_tr, y_tr)

    prob = model.predict_proba(X_te)[:, 1]
    pred = (prob > 0.5).astype(int)
    metrics = {
        "accuracy": round(accuracy_score(y_te, pred), 4),
        "precision": round(precision_score(y_te, pred), 4),
        "recall": round(recall_score(y_te, pred), 4),
        "f1": round(f1_score(y_te, pred), 4),
        "roc_auc": round(roc_auc_score(y_te, prob), 4),
        "n_train": int(len(X_tr)), "n_test": int(len(X_te)),
        "n_dga_train": int(np.sum(y_tr)), "n_legit_train": int(len(y_tr) - np.sum(y_tr)),
    }
    print("[train_dga] metrics:", json.dumps(metrics, indent=2))
    print("[train_dga] confusion matrix (rows: actual legit/dga):")
    print(confusion_matrix(y_te, pred))
    print(classification_report(y_te, pred, target_names=["legit", "dga"]))

    model.booster_.save_model(str(out / "dga_model.txt"))
    (out / "dga_features.json").write_text(json.dumps(
        {"feature_names": DGA_FEATURE_NAMES, "source": "offline-train"}))

    importance = sorted(zip(DGA_FEATURE_NAMES, model.feature_importances_),
                        key=lambda t: -t[1])
    (out / "feature_importance.json").write_text(
        json.dumps([{"feature": n, "gain": round(g, 4)} for n, g in importance]))

    if not args.no_shap:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import shap
            explainer = shap.TreeExplainer(model)
            sv = explainer.shap_values(X_te[:500])
            if isinstance(sv, list):
                sv = sv[1]
            plt.figure(figsize=(9, 4))
            shap.summary_plot(sv, X_te[:500], feature_names=DGA_FEATURE_NAMES,
                              show=False, plot_size=(9, 4))
            plt.tight_layout()
            plt.savefig(out / "shap_importance.png", dpi=120)
            print("[train_dga] SHAP summary saved to artifacts/shap_importance.png")
        except Exception as exc:
            print(f"[train_dga] SHAP unavailable: {exc}")

    (out / "model_card_dga.json").write_text(json.dumps({
        "model": "LightGBM binary classifier",
        "task": "DGA vs legitimate domain classification",
        "features": DGA_FEATURE_NAMES,
        "training_data": {
            "legit": "bundled top-domain corpus (ml/data/legit_domains.txt) + "
                     "subdomain/TLD augmentation",
            "dga": f"{args.n_dga} synthetic domains across 4 DGA family styles "
                   "(random letters, hex labels, word+digit, reversed word)",
        },
        "metrics": metrics,
        "threshold": {"alert": 0.65, "comment": "chosen for recall-leaning alerting"},
        "limitations": [
            "Synthetic DGA families approximate real DGA distributions; periodic "
            "retraining on fresh feeds recommended.",
            "Classifier sees query names only — no response or resolver context.",
        ],
    }, indent=2))
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"[train_dga] artifacts written to {out}/")


if __name__ == "__main__":
    main()
