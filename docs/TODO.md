# TODO / remaining work

## Blockers (demo won't be clean until resolved)

- **Port 8000 conflict.** A leftover process from another project
  (`python3 -m uvicorn backend.app.main:app`, PID 21293) holds host port 8000,
  which the diode API also binds. Current workaround: run the API internal-only
  via a temporary compose override (frontend at `:3000` still proxies to it).
  Decide: kill the other process, or remap diode's API to a free host port
  (e.g. `8001`) in `docker-compose.yml` + README.

- **Throughput target vs reality.** The dashboard/`docker-compose.yml` states a
  2000 flows/sec target, but the engine sustains ~1300–1600. Either lower the
  stated target to ~1500 (honest), or profile the remaining per-flow cost
  (IsolationForest `score_samples` on every TLS flow is the likely next
  hotspot) to close the gap.

## n8n

- **Activate the 3 workflows.** They import deactivated. n8n 2.x uses a
  versioned *publish* system, so headless activation via direct SQL
  (`active`, `activeVersionId`, `workflow_published_version`) did not register
  webhooks. Reliable path: toggle **Active** in the editor at `:5678` for each
  of Alert Routing / Weekly DGA Retrain / Drift-Triggered Retrain.
- **Slack routing needs `SLACK_WEBHOOK`** in `.env` (the `alert_routing` workflow
  NoOps without it).

## Verification / coverage

- Confirm the remaining attack types fire end-to-end (they start later in the
  sim schedule): `DNS_TUNNEL` (~t=700), `TLS_MALWARE` (~t=900), `DATA_EXFIL`
  (~t=1100). Unit tests cover them; only the live replay needs confirming.
- Check the **live Evaluation tab** (precision/recall vs ground truth) once all
  eight classes have episodes — not yet exercised end-to-end.
- Optional: add a CI workflow (the `tests/` Dockerfile + `make test` already
  exist; a GitHub Action would run them on push).

## Polish (nice-to-have)

- `PYTHONUNBUFFERED=1` in the simulator Dockerfile so `docker compose logs
  simulator` shows progress (currently block-buffered).
- README screenshot(s) of the dashboard.
- A `.env` entry / note for the API host port if remapped.
- Replace the ad-hoc `/tmp/diode-port-override.yml` with a committed,
  documented approach once the port-8000 decision is made.
