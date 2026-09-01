# Model cards

## 1. DGA domain classifier (LightGBM)

**Task**: binary classification of DNS query names — legitimate vs
DGA-generated.

**Features** (8): Shannon entropy of base label, label length, 3-gram anomaly
vs benign corpus, digit ratio, vowel ratio, label count, suspicious TLD flag,
hex-lookalike flag.

**Training data**:
- Negative: bundled corpus of ~350 popular domains + subdomain/TLD
  augmentation (≈600 samples)
- Positive: 12,000 synthetic domains from 4 DGA family styles (random
  letters, hex labels, word+digit, reversed word) in `ml/dga_domains.py`

**Hyperparameters**: 150 trees, lr 0.05, 31 leaves, subsample 0.8, colsample
0.9. Alert threshold 0.65 (recall-leaning).

**Metrics** (held-out 20% stratified split): run
`docker build -f ml/Dockerfile -t diode-ml . && docker run --rm -v $PWD/ml/artifacts:/app/artifacts diode-ml python -m ml.train_dga --out /app/artifacts`
to regenerate `ml/artifacts/metrics.json` (expected ROC-AUC > 0.98 on this
synthetic task).

**Limitations**: synthetic DGA lookalikes approximate, not replicate, real
families. The runtime drift monitor (PSI on entropy distribution) and
retraining loop exist precisely because DGA distributions shift over time.
Single-name classification ignores resolver-query context (NXDOMAIN rates,
clustering by source).

## 2. TLS metadata anomaly detector (IsolationForest)

**Task**: unsupervised anomaly detection on TLS session metadata.

**Features** (6): ClientHello size, ServerHello size, certificate depth,
handshake packet count, cipher-suite entropy, packet-size ratio.

**Training**: benign-only synthetic TLS metadata (reference, `ml/train_tls.py`);
the live engine instead trains from its own passively observed warmup traffic
(the correct approach under the one-way constraint).

**Decision**: anomaly strength >1.5 past the learned boundary → alert
(confidence 0.5–0.75). JA3 denylist hits are independent and fire at 0.9.

**Reference metrics**: see `ml/artifacts/model_card_tls.json` after running
`python -m ml.train_tls`. Expected FPR ≈ 5% at contamination 0.05 by
construction; recall on the synthetic malware distribution is high (>0.95).

**Limitations**: unsupervised = no ground-truth labels at runtime; real-world
client heterogeneity (OSes, browsers, middleboxes) inflates benign variance.

## 3. DDoS window-profile anomaly detector (IsolationForest)

**Task**: anomaly detection on 10s per-destination window profiles.

**Features** (6): flow count, packet rate, distinct sources, SYN ratio, UDP
ratio, byte asymmetry.

**Training**: benign-only synthetic window profiles (reference,
`ml/train_ddos.py`); live engine trains from warmup observation.

**Note**: rate/heuristic thresholds (SYN ratio, source entropy, pps) carry most
detection weight at high precision; the model adds coverage for non-threshold
attack shapes.

## 4. Heuristic detectors (C2, recon, exfil)

No trained parameters — the "model" is the stateful windowing logic and
thresholds documented in `docs/threat-model.md`. The C2 detector's spectral
peak ratio and the exfil EWMA baseline are adapted from observed traffic
during runtime (the exfil baseline is learned per source).

## Evaluation methodology

Live ground-truth evaluation (dashboard → Evaluation tab):
- attack flows carry labels on a side channel the engine never reads
- consecutive flows of one campaign = episode (60s gap rule)
- matched alert session = TP, unmatched session = FP, missed episode = FN
- per-class and overall precision/recall/F1 update continuously
