"""Detection engine entrypoint.

Warmup: collect benign traffic until the required span of *flow timestamps*
has passed (or a wall-clock cap), then fit unsupervised models — fully
offline, consistent with the one-way enclave constraint.

Main loop: consume flow records from Redis Streams, run all detectors,
fan alerts out to DB / dashboard / n8n.
"""

from __future__ import annotations

import asyncio
import json
import queue
import time

import redis.asyncio as redis
from redis.exceptions import ResponseError

from .alerts import AlertManager
from .config import Config
from .context import Context
from .dbwriter import DbWriter
from .detectors import ALL_DETECTORS
from .dga_model import DgaClassifier
from .metrics import Metrics
from .models import UnsupervisedModels
from .schema import Flow
from .windows import WindowStore

STREAM = "diode:flows"
GROUP = "diode-engine"
CONSUMER = "worker-1"


async def command_loop(ctx: Context) -> None:
    pubsub = ctx.redis.pubsub()
    await pubsub.subscribe("diode:commands")
    async for msg in pubsub.listen():
        if msg.get("type") != "message":
            continue
        try:
            data = json.loads(msg["data"])
        except Exception:
            continue
        if data.get("cmd") == "retrain":
            await ctx.retrain(data.get("model", "all"))
        elif data.get("cmd") == "drift":
            res = ctx.compute_drift()
            await ctx.redis.set("diode:drift", json.dumps(res))
            await ctx.redis.publish("diode:events", json.dumps({"event": "drift", **res}))
            if res.get("alarmed"):
                print(f"[drift] PSI={res['drift']} above threshold — auto-retraining DGA")
                await ctx.retrain("dga")


async def main() -> None:
    cfg = Config.from_env()
    # socket_timeout=None: the main loop uses a blocking XREADGROUP (block=1000);
    # a client-side socket timeout would abort those reads under load.
    r = redis.from_url(cfg.redis_url, decode_responses=True, socket_timeout=None)
    await r.ping()

    metrics = Metrics()
    metrics.start(cfg.metrics_port)

    db_queue: queue.Queue = queue.Queue()
    db_writer = DbWriter(cfg.database_url, db_queue)
    db_writer.start()

    print("[engine] loading DGA classifier...")
    dga = DgaClassifier.load()
    print(f"[engine] DGA classifier source: {dga.source}")

    ctx = Context(cfg, WindowStore(), UnsupervisedModels(), dga,
                  AlertManager(cfg, db_queue, r, metrics), r, metrics)
    detectors = [cls(ctx) for cls in ALL_DETECTORS]

    try:
        await r.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    except ResponseError:
        pass

    asyncio.create_task(command_loop(ctx))
    asyncio.create_task(throughput_pump(ctx))

    # ------------------------------------------------------------- warmup
    t0 = time.monotonic()
    ts_lo = ts_hi = None
    fitted = False
    print(f"[engine] warmup: waiting for {cfg.warmup_sim_seconds}s of flow-time "
          f"span (cap {cfg.warmup_wall_cap:.0f}s wall)...")
    last_log = 0.0
    flows = 0

    while True:
        batch = await r.xreadgroup(GROUP, CONSUMER, {STREAM: ">"},
                                   count=1000, block=1000)
        if not batch:
            if not fitted and _warmup_done(cfg, ts_lo, ts_hi, t0):
                fitted = True
                status = ctx.models.fit_all()
                print(f"[engine] warmup complete; models: {status}; "
                      f"samples: {ctx.models.status()}")
                await _event(ctx, "warmup_complete", ctx.models.status())
            continue

        for _, messages in batch:
            for mid, fields in messages:
                try:
                    flow = Flow.from_dict(json.loads(fields["f"]))
                except Exception as exc:
                    print(f"[engine] bad flow record: {exc}")
                    continue
                flows += 1
                metrics.flows.inc()
                ts_lo = flow.ts if ts_lo is None else min(ts_lo, flow.ts)
                ts_hi = flow.ts if ts_hi is None else max(ts_hi, flow.ts)

                for det in detectors:
                    for alert in det.process(flow):
                        ctx.manager.submit(alert)

                if time.monotonic() - last_log > 10:
                    last_log = time.monotonic()
                    metrics.window_keys.set(len(ctx.store))
                    print(f"[engine] flows={flows} | span={ts_hi - ts_lo:8.0f}s | "
                          f"window_keys={len(ctx.store)} | alerts={metrics.alert_total()} "
                          f"| db_written={db_writer.written}")

        try:
            await r.xack(STREAM, GROUP, *[mid for _, messages in batch
                                          for mid, _ in messages])
        except ResponseError:
            pass


def _warmup_done(cfg: Config, ts_lo: float | None, ts_hi: float | None,
                 t0: float) -> bool:
    if ts_lo is None or ts_hi is None:
        return time.monotonic() - t0 > cfg.warmup_wall_cap
    span = ts_hi - ts_lo
    return span >= cfg.warmup_sim_seconds or time.monotonic() - t0 > cfg.warmup_wall_cap


async def throughput_pump(ctx: Context) -> None:
    """Publish live throughput to the dashboard every second.

    Rate is computed as a delta over the actual elapsed wall time (not a fixed
    1s interval), because the processing loop is CPU-bound and may starve the
    event loop for longer than one second between samples.
    """
    last_flows = 0.0
    last_alerts = 0.0
    last_ts = time.time()
    while True:
        await asyncio.sleep(1)
        f = ctx.metrics.flows._value.get()
        a = float(ctx.metrics.alert_total())
        now = time.time()
        dt = now - last_ts
        fps = (f - last_flows) / dt if dt > 0 else 0.0
        aps = (a - last_alerts) / dt if dt > 0 else 0.0
        last_flows, last_alerts, last_ts = f, a, now
        ctx.metrics.throughput.set(fps)
        ctx.metrics.alert_rate.set(aps)
        try:
            await ctx.redis.publish("diode:metrics", json.dumps({
                "ts": now, "flows_per_sec": round(fps, 1),
                "alerts_per_sec": round(aps, 1),
                "alerts_total": int(a), "flows_total": int(f),
                "throughput_target": ctx.cfg.throughput_target,
            }))
        except Exception:
            pass


async def _event(ctx: Context, name: str, data: dict) -> None:
    try:
        await ctx.redis.publish("diode:events",
                                json.dumps({"event": name, **data}))
    except Exception:
        pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[engine] stopped")
