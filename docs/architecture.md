# Architecture

## The problem

Critical-infrastructure operators mirror gateway/peering traffic into a
monitoring enclave through a **one-way data diode**. The enclave sees
everything but has **no path back**: it cannot probe, complete handshakes, or
push mitigations. Any intelligence layer must work from pure passive
observation and produce *intelligence* — labelled alerts, confidence scores,
evidence — not actions.

## Design principles

1. **Read-only ingest.** The pipeline only reads. Nothing in `engine/` opens a
   socket toward the traffic source or destination. Flows arrive via Redis
   Streams; alerts leave via a *different* interface (dashboard pub/sub, DB,
   n8n) that has no connection to the ingest path.
2. **Metadata only.** TLS/QUIC sessions are analysed from JA3 fingerprints,
   ClientHello/ServerHello sizes, certificate depth, handshake packet counts
   and timing. No payload decryption anywhere in the codebase.
3. **Streaming.** Per-flow, bounded-latency processing with sliding windows
   (deque-based, pruned on every access). No batch stages.
4. **Ground-truth isolation.** The simulator writes attack labels to a
   *separate* stream (`diode:ground_truth`) that the engine never reads. This
   both enforces the constraint and enables honest live evaluation.
5. **Self-contained ML.** All models train from either bundled corpora or the
   engine's own passively observed warmup traffic. No external services are
   required at any point.

## Components

```
                       ┌────────────────────────────────────────────┐
                       │  SIMULATOR  (synthetic labelled traffic)   │
                       │  benign + 8 attack campaigns, 60x clock    │
                       └───────────────┬──────────────┬─────────────┘
                                   flows │            │ ground-truth labels
                                         ▼            ▼  (engine never reads)
                              ┌── diode:flows ── diode:ground_truth ──┐
                              │              Redis Streams            │
                              └───────┬──────────────────┬────────────┘
                                      │ XREADGROUP       │ (evaluator)
                                      ▼                  │
                        ┌──────────────────────────┐     │
                        │  ENGINE (asyncio worker) │     │
                        │  ─ window store          │     │
                        │  ─ 6 detectors           │     │
                        │  ─ DGA logistic regr.   │     │
                        │  ─ TLS/DDoS IsolationF.  │     │
                        │  ─ drift (PSI) + retrain │     │
                        └──────┬─────────┬─────────┴─────┘
                alerts ────────┤         │                │
                (pub/sub)      │         │                │
                diode:alerts   │  batched inserts         │
                               ▼         ▼                │
                     ┌──────────────┐ ┌───────────────┐   │
                     │  API (FastAPI)│ │ TimescaleDB   │◄──┘
                     │  WS + REST    │ │ (hypertable)  │
                     │  evaluator    │ └───────────────┘
                     └──────┬───────┘
                            │ WebSocket
                            ▼
                     ┌──────────────┐      ┌──────────────┐
                     │ React + Vite │      │     n8n      │
                     │  dashboard   │      │ alert routing│
                     └──────────────┘      │ + retraining │
                                           └──────────────┘
```

| Service | Role | Port |
|---|---|---|
| `simulator` | emits labelled synthetic flows + truth side-channel | — |
| `redis` | stream transport, pub/sub, command channel | 16379 (host) |
| `engine` | feature extraction, 6 detectors, ML, drift, Prometheus `/metrics` | 9100 |
| `db` | TimescaleDB hypertable for alerts | 5433 (host) |
| `api` | WebSocket + REST, live ground-truth evaluator | 8000 |
| `frontend` | React dashboard (nginx-served build) | 3000 |
| `n8n` | orchestration workflows (routing, retrain, drift) | 5678 |
| `prometheus` / `grafana` | optional `monitoring` profile | 9090 / 3001 |

## Data flow

1. Simulator emits flow records (JSON) at a configurable rate with a 60x
   simulated clock; attack campaigns repeat on a schedule.
2. Engine consumes via Redis consumer group, updates stateful windows keyed by
   source/destination/pair, runs six detectors per flow.
3. Detectors emit `Alert` records (standardized schema), which are deduplicated
   into *alert sessions* (cooldown + occurrence counting), then fanned out:
   - batched INSERT into the TimescaleDB hypertable
   - `PUBLISH diode:alerts` → API → WebSocket → dashboard
   - `POST` to the n8n webhook for CRITICAL/HIGH (best-effort, non-blocking)
4. Evaluator (inside API) consumes the truth stream, matches alert sessions to
   attack episodes, maintains per-class precision/recall/F1 live.
5. Engine periodically computes PSI drift on the DGA entropy distribution;
   drift above threshold auto-triggers retraining. n8n also offers scheduled
   retraining and drift-check workflows.

## Throughput target

Stated and demonstrated target: **2,000 flows/sec sustained** (simulator emits
~800 flows/sim-sec; engine throughput is measured in real time and exposed on
the dashboard and Prometheus as `diode_flows_per_sec`). The pipeline is a
single asyncio worker per stream consumer; Redis consumer groups allow
horizontal scaling of additional workers with no code changes.

## Alert schema (v1.0)

```json
{
  "schema_version": "1.0",
  "alert_id": "a1b2c3d4e5f6",
  "ts": 1725192000.0,
  "threat_class": "C2_BEACON",
  "severity": "HIGH",
  "confidence": 0.87,
  "key": "10.0.1.50",
  "flow_id": "f5e3...",
  "src_ip": "10.0.1.50",
  "dst_ip": "198.51.100.10",
  "src_port": 40231,
  "dst_port": 443,
  "proto": "tcp",
  "evidence": { "inter_arrival_cv": 0.02, "mean_interval_s": 60.1, "...": "..." },
  "explanation": "7 flows to 198.51.100.10:443 with mean interval 60s ...",
  "occurrences": 3
}
```

## Model lifecycle

- **Warmup** — engine fits IsolationForest models (TLS metadata, DDoS window
  profiles) from the first ~3 minutes (flow-time) of benign-only traffic.
- **DGA classifier** — logistic regression trained on bundled legit-domain
  corpus + synthetic DGA families, either at image build / offline script or
  at runtime (fits in <1 s).
- **Drift** — PSI over rolling DGA entropy windows; alarm at 0.25.
- **Retraining** — engine command channel (`diode:commands`), n8n cron, or
  drift auto-trigger; fully in-process, no external data.
