# Progress log

Record of work completed to get the pipeline running end-to-end. The initial
commit (`437233a`) was structurally complete but never actually ran: the
simulator dropped every flow, the C2 simulator hung, and the engine crashed on
redis-py 8. All of the following are committed.

## Commit `8aa703d` — "Make the pipeline actually run end-to-end"

### Simulator
- **Sync, pipelined emitter** (`emit.py`): `emit_flow` was `async` but the
  synchronous scenario `tick` methods called it without awaiting — every flow
  was silently dropped. Switched to a synchronous `redis` client and buffer
  flows, flushed in one `pipeline(transaction=False)` per tick.
- **C2 beacon infinite loop** (`scenarios.py`): `while due <= sim_ts` updated
  `self.hosts[host]` but never the local `due`, so the loop spun forever once a
  host came due. Fixed by advancing the local variable.
- **Attack rate caps**: SYN-flood `3000 → 120` and UDP-amp `1000 → 80`
  flows/sim-sec. The old rates (×60 sim clock) emitted far more than the engine
  could process; the lower rates still comfortably trip the detectors.

### Engine
- **redis pin + timeout**: `redis>=5.0,<8` and `socket_timeout=None` — redis-py
  8 changed the default socket timeout to 5 s, which aborted the blocking
  `XREADGROUP` under load and crashed the worker.
- **DGA runtime model → logistic regression** (`dga_model.py`): LightGBM has a
  ~1.5 ms fixed per-call Python overhead that only amortizes under batching;
  a one-flow-at-a-time stream can't batch. Logistic regression reaches the same
  ROC-AUC (~1.0 on this task) at ~0.3 ms/call and trains in <1 s (was ~12 s).
  LightGBM remains in `ml/train_dga.py` for the offline model card / SHAP.
- **`_roc_auc` fix**: sorted descending but used the ascending-rank formula, so
  it reported AUC 0.0 for a perfectly-separated model.
- **`add_sample` O(3000) degradation** (`models.py`): after 3000 samples every
  TLS flow copied a 3000-element list; replaced with `deque(maxlen=3000)`. This
  was the main cause of the engine decaying from ~1500 to ~60 flows/sec.
- **Throughput rate** (`main.py`): `flows_per_sec` was a raw counter delta, not
  divided by elapsed time, so the dashboard showed a flat ~1000 line. Now
  computes `delta / dt`.
- **C2 SYN-only exclusion** (`c2.py`): SYN-flood traffic (spoofed sources →
  victim) was being flagged as botnet beacons (83 false C2 alerts). Added
  `flow.is_syn_only` to the pre-filter.
- **DGA n-gram corpus** (`features.py`): kept only trigrams seen ≥3×, so legit
  domains whose trigrams appear once (e.g. `google`) scored 100% anomalous.
  Now keeps all observed trigrams (`c >= 1`).
- **DGA alert threshold** `0.65 → 0.80` (`dga_dns.py`): the old threshold flagged
  legitimate long names (`cloudflarestatus.com`, `paloaltonetworks.com`,
  `americanairlines.com`). 0.80 gives zero false positives on the corpus at
  ~99.6% DGA recall.

### API / dashboard
- **`eval.catch_up()` hang** (`eval.py`): `xread(block=0)` blocks forever on an
  empty ground-truth stream, so the API never finished startup. Changed to
  `block=1000`.
- **`/api/stats` SQL** (`db.py`): `to_timestamp(timestamptz - number)` was a type
  error; replaced with an `interval` comparison.
- **`recent_alerts` returns epoch `ts`** (`db.py`): the snapshot returned `time`
  (ISO string) while the WebSocket path returned `ts` (epoch), so the LiveFeed
  crashed with `RangeError: Invalid time value` once alerts existed.

### Config / docs
- **Simulator `SPEED 60 → 4`** (`docker-compose.yml`): the 60× sim clock emitted
  ~36k flows/real-sec, which neither Redis nor the single-process engine could
  sustain (the backlog grew unboundedly). 4× is sustainable and still fast
  enough to demo.
- Added **`README.md`**; updated `docs/model-cards.md`, `docs/architecture.md`,
  `docs/threat-model.md` for the logistic-regression runtime model and 0.80
  threshold.

## Commit `9bc2709` — "Add reproducible n8n workflow import"

- Mount `n8n/` into the container at `/opt/workflows`.
- Add `make n8n-import` (stops n8n, imports, restarts) to avoid the
  CLI/live-process SQLite race that silently dropped imported workflows.

## Verification

- `pytest`: **32 passed**.
- Full stack (`docker compose up`) runs and detects attacks live:
  `DDOS_SYN_FLOOD`, `DDOS_UDP_AMPLIFICATION`, `C2_BEACON`, `DGA_DOMAIN`,
  `RECON_SCAN` confirmed in TimescaleDB with correct classes and no false
  positives during warmup.
- Engine sustains ~1300–1600 flows/sec (real time) against the simulator.

## Throughput — micro-batched IsolationForest scoring (uncommitted)

- **`models.py`**: added `_AnomalyModel.score_batch()`; `score()` now delegates to
  it. `IsolationForest.score_samples` has a fixed per-call overhead (tree walk
  setup in Python) that only amortizes under batching — same lesson as the DGA
  LightGBM→logistic switch, but here we keep the 200-tree model and batch the
  *scoring* instead.
- **`tls_malware.py`**: the behavioural-anomaly path buffers up to 32 TLS flows
  and scores them in one `score_batch` call (flushing early if flow-time gaps
  exceed 1s so sparse traffic still resolves). The JA3 denylist stays
  synchronous, and `add_sample` (warmup/retrain buffer) is unaffected.
- **`ddos.py`**: replaced six separate passes over the per-destination window
  with a single pass, and micro-batched its window-profile `score_batch` (the
  DDOS_ANOMALY single-sample score was the next-largest cost after TLS).
- **`main.py` warmup bug**: `fit_all()` only ran in the empty-`xreadgroup`
  branch, so under a sustained backlog the models *never* fitted and the
  IsolationForest detectors silently never scored. Moved the warmup check to
  the top of the loop so models fit as soon as the flow-time span threshold is
  met.
- **`docker-compose.yml`**: redis now runs `--save ""` (fully ephemeral). The
  VM disk filled during the first live run, putting redis into `MISCONF`
  stop-writes and stalling the pipeline; RDB snapshots are pointless here.
- **Verified live** (`docker compose up`): warmup completes, TLS+DDOS models
  fit, and the engine sustains **~2.16–2.21k flows/sec** (target 2,000) with
  attacks firing end-to-end (DDOS_SYN_FLOOD, DGA_DOMAIN, etc. written to
  TimescaleDB). Locally the full detector pipeline now runs ~10.6k flows/sec.
- Tests: `test_tls_score_batch_matches_single` (batch == single element-wise)
  and `test_tls_batched_behavioural_anomaly` (in-distribution batch flush
  raises no false positives).
