# Diode Watch

**Passive, one-way threat detection for critical-infrastructure enclaves.**

Critical-infrastructure operators watch their gateway and peering links through
a **hardware data diode** — a mirror that copies traffic into a monitoring
enclave in one direction only. The enclave sees everything crossing the link,
but has **no physical or protocol-level path back**: it cannot probe, complete
a handshake, or push a mitigation. That removes an entire class of attack (a
compromised monitoring box becoming a pivot into the core network) at the cost
of forcing any intelligence layer to work purely from what it can passively
observe.

**Diode Watch** is an AI/ML pipeline that lives entirely inside that enclave.
It ingests a one-directional stream of IP flow records, detects / classifies /
scores six threat families in near real time, and emits standardized,
evidence-backed alerts to a live dashboard. Everything is open source, runs on
free-tier tools, and is designed to demo well at a hackathon.

```
┌──────────────┐   flows   ┌──────────────┐  alerts  ┌──────────────┐
│  SIMULATOR   │──────────▶│    ENGINE    │─────────▶│  DASHBOARD   │
│ labelled     │  Redis    │ 6 detectors  │ WS+DB    │ React live   │
│ traffic      │  Streams  │ + ML models  │          │ feed + eval  │
└──────────────┘           └──────┬───────┘          └──────────────┘
                                  │ n8n webhook
                                  ▼
                          ┌──────────────┐
                          │     n8n      │  alert routing + retrain
                          └──────────────┘
```

## What it detects

| Threat | Approach |
|---|---|
| **Volumetric / protocol DDoS** | per-destination 10s window — flow rate, source-IP entropy, SYN ratio, UDP amplification ratio + IsolationForest window profile |
| **Botnet C2 beaconing** | inter-arrival coefficient-of-variation + FFT periodogram peak significance |
| **DGA domains / DNS tunnelling** | logistic-regression classifier (entropy, n-gram anomaly, TLD…) + tunnelling heuristics |
| **Malware inside TLS** | JA3 denylist + IsolationForest over ClientHello/sizes/cert-depth/timing — **no decryption** |
| **Recon / port scanning** | per-source fan-out (vertical + horizontal) counting |
| **Data exfiltration** | out/in byte ratio + per-host EWMA volume anomaly |

Every alert is a **versioned JSON record** with timestamp, flow id, threat
class, severity, confidence score, and supporting evidence features — see
`docs/architecture.md` for the v1.0 schema.

## Architectural constraints (all honoured)

- **Read-only ingest** — no code path in `engine/` initiates traffic toward
  observed IPs; the only outbound HTTP is the optional n8n webhook inside the
  enclave. The simulator writes ground-truth labels to a *separate* Redis
  stream the engine never reads.
- **No payload decryption** — TLS/QUIC is analysed from JA3 fingerprints,
  ClientHello/ServerHello sizes, certificate depth, and timing only.
- **Streaming, not batch** — bounded-latency per-flow processing with sliding
  windows; stated throughput target **2,000 flows/sec sustained**, measured
  live and exposed on the dashboard and Prometheus.
- **Self-contained ML** — all models train from bundled corpora or the
  engine's own passively observed warmup traffic. No external services needed.

## Quick start

Requires Docker + Docker Compose.

```bash
git clone https://github.com/praneshnikhar/diode-watch.git
cd diode-watch
docker compose up -d --build        # or: make up
```

Open **http://localhost:3000** for the dashboard. The simulator emits benign
traffic immediately; after the engine has learned its ~3-minute benign
baseline (warmup), attack campaigns begin and alerts start streaming in.

| Service | URL | Purpose |
|---|---|---|
| Dashboard (React) | http://localhost:3000 | live feed, overview charts, live eval |
| API (FastAPI) | http://localhost:8000/docs | REST + WebSocket backend |
| n8n | http://localhost:5678 | alert routing + retrain orchestration |
| Redis | localhost:16379 | streams / pub-sub / command channel |
| TimescaleDB | localhost:5433 | alert hypertable |
| Prometheus* | http://localhost:9090 | engine metrics |
| Grafana* | http://localhost:3001 | dashboards (password `diode`) |

`*` optional — start with `docker compose --profile monitoring up -d`.

## Useful commands

```bash
make up          # build + start everything
make logs        # tail all service logs
make test        # run the unit test suite (isolated container)
make train       # offline DGA training → ml/artifacts/
make ps          # service status
make down        # stop everything
```

## Repository layout

```
engine/     asyncio detection worker: window store, 6 detectors, DGA logistic
            regression, TLS/DDoS IsolationForest, drift (PSI) + retrain,
            Prometheus /metrics
simulator/  synthetic labelled traffic (benign + 8 attack campaigns, 60x clock)
ml/         feature engineering, DGA generators, offline training + model cards
dashboard/  FastAPI backend (WebSocket relay + live ground-truth evaluator)
            and React/Vite/Recharts frontend
n8n/        importable workflows: alert routing, weekly retrain, drift retrain
monitoring/ Prometheus scrape config + Grafana provisioning
docs/       architecture.md · threat-model.md · model-cards.md
tests/      unit tests for detectors, features, windows, alerts, simulator
```

## The ML in one paragraph

The pipeline is a **hybrid**: rock-solid stateful heuristics carry DDoS, recon,
and exfil detection, while three trained models add the ML layer. A
**logistic-regression classifier** distinguishes DGA-generated domains from
legitimate ones (entropy, 3-gram anomaly vs a bundled benign corpus,
digit/vowel ratio, TLD, hex-lookalike) — chosen for sub-millisecond per-sample
streaming latency, with a LightGBM model trained offline for feature-importance
analysis. Two **IsolationForest** models flag anomalous TLS session metadata
and anomalous DDoS window profiles, trained unsupervised on the engine's own
benign warmup traffic. A **PSI drift monitor** watches the DGA
entropy distribution and auto-triggers retraining — closing the loop without
ever leaving the enclave. See `docs/model-cards.md` for features, training
data, and metrics; run `make train` to regenerate them.

## Live evaluation

Because the simulator emits ground-truth labels on a side channel the engine
never reads, the dashboard's **Evaluation** tab shows honest, continuously
updated precision / recall / F1 per threat class — the whole point of the
one-way constraint, demonstrated rather than asserted.

## License

MIT — see `LICENSE`.
