# Diode Watch — Judge Explainer

Everything you need to walk a judge through the project: the dashboard, the n8n
workflows, the Slack alerts, and the meaning of every number on screen. Written
as a reference + talking-points document. Skim the **TL;DR** for a 60-second
pitch, then use the sections to go deep on whatever they ask.

---

## TL;DR — the 60-second pitch

Diode Watch is an **AI/ML intrusion-detection pipeline that lives inside a
one-way data diode**. A data diode lets a monitoring enclave *see* all traffic
on a critical-infrastructure link but gives it **no way to send anything back** —
so it can never probe, never complete a handshake, and, critically, can never be
compromised into a pivot back into the core network. Diode Watch works purely
from passively observed IP flow metadata (no packet contents, no decryption),
detects **6 threat families** in near real time, and emits **standardized,
evidence-backed alerts** to a live dashboard and to n8n/Slack orchestration.

The whole thing is a self-contained, time-lapse simulation: a labelled traffic
simulator feeds Redis, a streaming detection engine processes ~2,000 flows/sec,
and a React dashboard shows live alerts plus an honest, continuously-updated
precision/recall evaluation against ground truth.

---

## 1. The system at a glance

```
┌──────────────┐   flows      ┌──────────────┐   alerts   ┌──────────────┐
│  SIMULATOR   │────────────▶ │    ENGINE    │──────────▶ │  DASHBOARD   │
│  labelled     │   Redis     │ 6 detectors  │  WS + DB   │ React live   │
│  traffic      │   Streams   │ + ML models  │            │ feed + eval  │
└──────────────┘              └──────┬───────┘            └──────────────┘
                                     │ HIGH/CRITICAL
                                     │ (best-effort)
                                     ▼
                              ┌──────────────┐
                              │     n8n      │  → Slack alerts
                              │ 3 workflows  │  → scheduled retrains
                              └──────────────┘
```

- **Simulator** — generates synthetic benign traffic plus 8 attack campaigns.
  Every flow carries a `ts` that is **simulation time** (the "time-lapse clock"):
  sim time advances 4× faster than real wall-clock (`SPEED=4`). Attack flows
  also carry a ground-truth label written to a **separate** Redis stream
  (`diode:ground_truth`) that the detection engine **never reads** — this is
  what makes the dashboard's evaluation honest.
- **Engine** — a single asyncio worker that consumes flows from a Redis stream,
  runs six detectors, and fans alerts out to TimescaleDB (persistence), Redis
  pub/sub (dashboard), and — for HIGH/CRITICAL only — the n8n webhook.
- **API/dashboard** — FastAPI backend relays pub/sub messages over WebSocket and
  runs the live ground-truth evaluator; a React frontend renders the Live Feed,
  Overview, Evaluation, and About tabs.
- **n8n** — three workflows: alert routing to Slack, hourly drift-triggered
  retraining, and weekly DGA retraining.

---

## 2. The one-way data diode — the core idea to lead with

A hardware data diode is a network device that copies traffic in **one direction
only** (mirror → monitoring enclave) and physically guarantees nothing flows
back. Operators like this because:

- The monitoring box cannot be used to *attack back* into the network even if it
  is compromised.
- It cannot alter traffic, inject packets, or complete handshakes.

The consequence: any intelligence layer has to work from **passive observation
only**. Diode Watch turns that constraint into a design checklist and shows the
judges it honours all of it:

1. **Read-only ingest** — the engine never initiates traffic toward observed
   IPs. Its only outbound call is the optional n8n webhook (inside the enclave).
2. **No decryption** — TLS/QUIC is analysed from JA3 fingerprints,
   ClientHello/ServerHello sizes, cert depth, and timing metadata only.
3. **Streaming, not batch** — bounded-latency per-flow processing with sliding
   windows; stated throughput target **2,000 flows/sec sustained**, measured
   live.
4. **Self-contained ML** — every model trains from bundled corpora or from the
   engine's own passively observed warmup traffic. No external services, no
   labels, no feedback path required — which is exactly what a one-way enclave
   forces.

---

## 3. The dashboard

Open **http://localhost:3000**. Four tabs: **Live Feed**, **Overview**,
**Evaluation**, **About**.

### 3.1 Header (always visible)

- **`● stream live / reconnecting`** — WebSocket connection to the API. If it
  shows "reconnecting", the API or the stack isn't up.
- **`flows/s`** — the engine's **real-time** processing rate (flows processed
  per real second), updated every second. Target is 2000/s.
- **`alerts`** — number of alert sessions currently in the live-feed window
  (latest 300).
- **`target 2000/s`** — the stated throughput goal, from the engine config.
- **`passive · read-only · no decryption`** — the marketing reminder of the
  design constraints.

---

### 3.2 Live Feed tab

Each row is one **alert session**. Example:

```
[HIGH]  C2_BEACON   10.0.1.50:40231 → 198.51.100.10:443  tcp  ▓▓▓▓▓▓▓▓▓░ 87%  ×3  00:12:40
```

Field-by-field:

| Field | Meaning |
|---|---|
| **Severity badge** | `CRITICAL` (red) / `HIGH` (orange) / `MEDIUM` (yellow) / `LOW` (gray). Derived from threat class + confidence (see §6). |
| **Threat class** | One of the 6 families: `DDOS_SYN_FLOOD`, `DDOS_UDP_AMPLIFICATION`, `DDOS_VOLUMETRIC`, `DDOS_ANOMALY`, `C2_BEACON`, `DGA_DOMAIN`, `DNS_TUNNEL`, `TLS_MALWARE`, `RECON_SCAN`, `DATA_EXFIL`. |
| **src:port → dst:port** | The 5-tuple of the flow that triggered it. `10.0.1.x` are internal hosts; `203.0.113.x` / `198.51.100.x` are documentation-range "internet" addresses. |
| **proto** | Transport protocol: `tcp`, `udp`, or `icmp`. |
| **Confidence bar + %** | The detector's confidence in the alert (0–100%). A *high* confidence is a strong signal, not a ground-truth guarantee. |
| **×N badge** | **Occurrence count.** When the *same* `(threat_class, source)` fires again while an alert session is still "hot" (within its cooldown + 300 s session gap), n8n/engine does **not** create a new alert — it increments `occurrences` on the same `alert_id`. So `×3` means **this alert session has fired 3 times** and has been deduplicated into one row. |
| **Time** | The **simulation clock** when the alert fired (elapsed sim time as `HH:MM:SS`, time-lapse). |

Click a row to expand the **evidence JSON** — the concrete features that fired
(see §7 for what each class shows).

### 3.3 Overview tab

Four summary cards:

| Card | Meaning |
|---|---|
| **Throughput (flows/sec)** | Live processing rate, real time. Target 2000. |
| **Flows processed** | **Cumulative** total the engine has processed **since this engine process started**. It is a monotonic counter, not a rate — that's why it reaches millions on a long-running demo. Resets to 0 if the engine container restarts. |
| **Alert sessions** | Distinct alert sessions currently in the live-feed window. |
| **Alerts/sec** | Current alert emission rate (delta per real second). |

Charts:

- **Alerts by threat class** (bar) — raw count of each threat class in the live
  feed window.
- **Severity distribution** (pie) — share of CRITICAL/HIGH/MEDIUM/LOW in the
  window.
- **Throughput graph** — the line chart. **Y-axis = flows/sec. X-axis =
  simulation time (the time-lapse clock)**, shown as `MM:SS` (or `H:MM:SS`)
  elapsed sim time, e.g. `56:00` means 56 simulation-minutes have elapsed
  (≈14 real minutes at 4× speed). Each plotted point is one per-second metrics
  sample; the window holds the last 180 samples (~3 min). Because sim time runs
  4× wall clock, the curve is stretched 4× compared to real time — this is
  intentional (it's a time-lapse sim). Hover a point for the exact value.
- **Engine events** — a live log of lifecycle events from the engine (see §8):
  `warmup_complete`, `retrain`, `drift`.

### 3.4 Evaluation tab — the honest scoring

The tab shows live **precision / recall / F1**, overall and per threat class,
plus a table of **TP / FP / FN**. This is the strongest technical talking point
for judges because it is *demonstrated, not asserted*:

- The simulator labels every attack flow on `diode:ground_truth`, a Redis stream
  the **detection engine never reads** (honours the one-way constraint — the
  detector truly has no labels).
- The **evaluator runs in the API**, reads that truth stream, and matches
  *alert sessions* against *attack episodes*:

  - **Episode** = consecutive attack flows of the same class+source within a
    60 s gap.
  - **TP** = an alert session matched within ±15 s of any episode flow (and
    matching class, with DDoS classes grouped).
  - **FP** = an alert session with no matching episode.
  - **FN** = an episode with no alert after a 120 s grace window.

- **Precision = TP/(TP+FP)** (of everything we alerted, how much was real).
- **Recall = TP/(TP+FN)** (of all real attacks, how many we caught).
- **F1** = harmonic mean of the two.

Evaluation is **campaign-level** (episodes), not per-flow — the right unit for
an operator who cares "did we catch the campaign?".

### 3.5 About tab

Static reference: what the project is, the architectural constraints, the
threat-coverage table (threat → approach), and the stack:
Python 3.12 · Redis Streams · TimescaleDB · scikit-learn / LightGBM / scipy ·
FastAPI + WebSockets · React + Vite + Recharts · n8n · Prometheus/Grafana ·
Docker Compose — 100% open source.

---

## 4. The alert schema — every field

Every alert is a versioned JSON record (`schema_version: "1.0"`). Example:

```json
{
  "schema_version": "1.0",
  "alert_id": "a1b2c3d4e5f6",
  "ts": 3600.0,
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
  "evidence": { "inter_arrival_cv": 0.02, "mean_interval_s": 60.1 },
  "explanation": "7 flows to 198.51.100.10:443 with mean interval 60s ...",
  "occurrences": 3
}
```

| Field | Meaning |
|---|---|
| `schema_version` | Version of the alert format (v1.0). |
| `alert_id` | A stable id for the *session*. Re-alerts of the same source bump `occurrences` instead of making a new id. |
| `ts` | **Simulation time** when the alert fired (time-lapse clock, seconds since sim start). |
| `threat_class` | Which family fired (see §5). |
| `severity` | Operational priority CRITICAL/HIGH/MEDIUM/LOW (see §6). |
| `confidence` | 0–1 detector confidence (displayed as %). |
| `key` | The entity the session is keyed on — the source IP, or destination IP for DDoS — used for dedup/cooldown. |
| `flow_id` | The specific flow record that triggered this alert. |
| `src_ip/dst_ip/src_port/dst_port/proto` | The flow's 5-tuple. |
| `evidence` | The concrete features that fired (auditability). |
| `explanation` | Human-readable sentence for the analyst / Slack. |
| `occurrences` | How many times this session has fired (dedup count). |

---

## 5. The six threat families & what each `evidence` shows

### 1) Volumetric / protocol DDoS — `DDOS_SYN_FLOOD`, `DDOS_UDP_AMPLIFICATION`, `DDOS_VOLUMETRIC`, `DDOS_ANOMALY`
- Per-destination 10 s window: flow rate, distinct-source count (spoofed-source
  entropy proxy), SYN-only ratio, UDP ratio, in/out byte asymmetry.
- Fires: ≥40 flows & ≥20 sources & SYN ratio ≥0.85 (`DDOS_SYN_FLOOD`); ≥40 flows
  & UDP ≥0.8 & byte-asymmetry ≥20 & ≥10 sources (`DDOS_UDP_AMPLIFICATION`);
  per-source >1500 flows/s (`DDOS_VOLUMETRIC`); plus an IsolationForest anomaly
  over the window profile (`DDOS_ANOMALY`).
- `evidence` shows `flows`, `distinct_src`, `syn_ratio`/`udp_ratio`,
  `pps`, `bytes_asymmetry`, `anomaly_strength`.

### 2) Botnet C2 beaconing — `C2_BEACON`
- Looks for *periodic* connections: inter-arrival coefficient of variation (CV)
  + FFT periodogram peak/mean ratio, over a 15-min per-`(src,dst,port)` history.
- `evidence` shows `n_beacons`, `inter_arrival_cv`, `mean_interval_s`,
  `periodogram_peak_ratio`, `dst`.

### 3) DGA domains & DNS tunnelling — `DGA_DOMAIN`, `DNS_TUNNEL`
- A logistic-regression classifier scores query names (entropy, 3-gram anomaly
  vs a bundled benign-domain corpus, digit/vowel ratio, TLD, hex-lookalike);
  threshold 0.80 → `DGA_DOMAIN`. Long high-entropy names (or TXT/NULL-heavy) →
  `DNS_TUNNEL`.
- `evidence` shows `domain`, `entropy`, `length`, `qtype`, `ngram_anomaly`, and
  for the ML path `prob`, `method`.

### 4) Malware inside TLS — `TLS_MALWARE` (no decryption!)
- Two independent signals: (a) **JA3 denylist** — ClientHello fingerprint matches
  a known malware family (TrickBot, Emotet, Qakbot, Cobalt Strike, …) → fires at
  0.9 confidence; (b) **IsolationForest** anomaly over ClientHello/ServerHello
  sizes, cert depth, handshake count, cipher entropy vs the learned benign
  profile → fires at 0.5–0.75.
- `evidence` shows `ja3`, `family` (on denylist), `anomaly_strength`,
  `client_hello_size`, `handshake_packets`, `cipher_entropy`.

### 5) Recon / port scanning — `RECON_SCAN`
- Per-source 60 s window of SYN-only probes: ≥64 ports on one host (vertical),
  ≥100 hosts (horizontal), or ≥150 distinct pairs (fan-out).
- `evidence` shows `direction`, `distinct_ports_on_target` / `distinct_hosts` /
  `distinct_pairs`, `total_probes`, `window_s`.

### 6) Data exfiltration — `DATA_EXFIL`
- Per-(src,dst) 10-min window: out/in byte ratio (>8) with >50 KB outbound; plus
  a per-source EWMA baseline where a single transfer >4σ above normal also fires.
- `evidence` shows `bytes_out`, `bytes_in`, `out_in_ratio`, or `z_score`,
  `baseline_mean`.

---

## 6. Severity & confidence — how they relate

**Confidence** is the detector's strength estimate (0–1). It comes from the
heuristics/models, e.g. SYN-flood confidence grows with the window size
`min(0.95, 0.6 + n/300)`, the JA3 denylist is fixed at 0.9, DGA uses the model
probability.

**Severity** is then derived from threat class + confidence:

| Class | Severity rule |
|---|---|
| `DDOS_*`, `DATA_EXFIL` | `CRITICAL` if conf ≥ 0.8, else `HIGH` |
| `C2_BEACON`, `DNS_TUNNEL`, `TLS_MALWARE` | always `HIGH` |
| `DGA_DOMAIN`, `RECON_SCAN` | `HIGH` if conf ≥ 0.9, else `MEDIUM` |
| everything else | `LOW` |

Why two signals? A *high-confidence heuristic* (e.g. a denylist hit) and a
*high-severity* alert (e.g. data exfiltration) mean different things to an
operator, and severity is what drives operational routing (→ n8n/Slack only gets
HIGH and CRITICAL).

---

## 7. n8n workflows (http://localhost:5678)

Three workflows, all imported from `n8n/*.json` and activated via
`make n8n-import` (which uses the headless `publish:workflow` model of n8n 2.x —
this was a hard-won fix: without a fixed `webhookId` on the Webhook node, the
production path becomes `/{workflowId}/{nodeName}/...` instead of `/diode-alert`).

### 7.1 Alert Routing — the Slack pipeline
```
Webhook (POST /webhook/diode-alert)
   → IF body.severity is HIGH or CRITICAL?
        true  → IF $env.SLACK_WEBHOOK is set?
                   true  → HTTP POST → Slack channel
                   false → NoOp
        false → NoOp (MEDIUM/LOW dropped)
```
- The engine POSTs **only HIGH/CRITICAL** alerts here (best-effort, non-blocking,
  3 s timeout — never allowed to stall detection).
- Requires `SLACK_WEBHOOK` in `.env` (gitignored) and
  `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` so `$env.SLACK_WEBHOOK` is readable in
  node expressions.
- Slack message format:
  `DIODE-WATCH [HIGH] C2_BEACON — 10.0.1.50 -> 198.51.100.10 (conf 0.87). <explanation>`

### 7.2 Drift-Triggered Retrain — the self-healing loop
```
Schedule (hourly) → POST /api/drift-check (asks engine to compute PSI)
   → PSI > 0.25?  true → POST /api/retrain {model: dga} → engine retrains DGA
                 false → NoOp
```
- **PSI (Population Stability Index)** measures how much the distribution of DGA
  query entropy has drifted from the baseline learned early in the run. If the
  traffic has drifted enough (PSI > 0.25), the DGA model is automatically
  retrained from the fresh corpus — **closing the ML loop entirely inside the
  enclave, with no external feedback**.

### 7.3 Weekly DGA Retrain
```
Schedule (cron "0 2 * * 0", Sundays 02:00) → POST /api/retrain {model: dga}
   → HTTP 2xx? → NoOp
```
A simple scheduled safety-net retrain so the DGA model is refreshed at least
weekly regardless of drift signals.

---

## 8. Engine events (the "Engine events" panel)

The engine publishes lifecycle events on Redis pub/sub, which the dashboard
shows as JSON lines:

- `warmup_complete` — the engine collected enough benign traffic (180 s of
  *simulation* time) and **fitted** the TLS and DDoS IsolationForest models.
  Before this, those detectors are warming up (no scoring).
- `retrain` — a retrain happened (manual, n8n-triggered, or drift-triggered),
  with per-model success and metrics.
- `drift` — the PSI drift value computed on demand, with `alarmed: true/false`.

The `alarmed` drift also triggers automatic DGA retraining in-engine.

---

## 9. Key numbers to rattle off

| Thing | Value |
|---|---|
| Throughput target (real time) | **2,000 flows/sec sustained** (live-measured ~2,160–2,210) |
| Simulator rate / speed | 800 flows/sim-sec at `SPEED=4` (≈3,200 real/s emitted) |
| Warmup | 180 sim-seconds benign baseline (≈45 real s) before ML fits |
| Models | DGA logistic regression · TLS IsolationForest (200 trees) · DDoS IsolationForest |
| ML scoring | micro-batched (32 vectors/call) so scoring isn't the bottleneck |
| Alert cooldowns | e.g. C2 45 s, DGA 20 s, TLS 30 s; sessions reset after 300 s |
| Storage | TimescaleDB hypertable (time-partitioned alert table) |
| Eval matching | alert-session ↔ episode within ±15 s; FN grace 120 s |

---

## 10. Suggested demo flow for the judges

1. **Pitch** (30 s) — one-way diode, passive-only, 6 families, live eval (§ TL;DR).
2. **Start fresh** (optional): `docker compose down -v && docker compose up -d --build && make n8n-import`, or just `make up` if already built.
3. **Live Feed** — show real alerts streaming; expand one and walk the evidence
   JSON; point out the ×N dedup and the confidence bar.
4. **Overview** — throughput card near 2000; the time-lapse x-axis of the graph;
   flows-processed counter; severity pie.
5. **Evaluation** — this is the money shot: real TP/FP/FN, precision/recall/F1,
   and explain the ground-truth side channel proves the detector is label-free.
6. **About** — the constraints table (read-only, no decryption, streaming).
7. **n8n** — open a workflow and show the alert-routing path → Slack; show the
   drift-retrain loop; (optional) show a Slack notification.
8. **Hard questions** — "why passive-only?" (diode), "why no decryption?"
   (TLS 1.3 + the diode), "how do you know it works?" (live eval vs ground
   truth), "what happens when traffic changes?" (PSI drift → auto-retrain),
   "how does it scale?" (Redis consumer groups, single asyncio worker,
   2000 flows/sec).

---

## 11. Common judge questions — quick answers

- **"Is it real network traffic?"** No — it's a high-fidelity labelled
  simulation (documentation-range IPs, realistic distributions) run as a
  time-lapse so a full attack timeline fits in a few minutes. The detection
  pipeline itself is what would sit on a real diode tap.
- **"Why 56:00 on the graph?"** That's the **simulation clock** — elapsed sim
  minutes, time-lapse at 4× real time. Not UTC wall-clock.
- **"Why did flows-processed hit millions?"** It's a **cumulative counter since
  engine start**; at ~2,000 flows/sec it climbs into the millions over a long
  demo. It resets on engine restart.
- **"How is precision/recall honest if it's a sim?"** The ground truth travels
  on a stream the detector never reads; the numbers are computed independently
  in the API. The one-way constraint is exercised, not faked.
- **"What would a real deployment need?"** A tap/mirror into the enclave, the
  flow-metadata parser, and optionally n8n for operator routing — the ML,
  windows, alerting, and eval are all here.