"""Dashboard API: WebSocket live feed + REST endpoints.

WebSocket message types:
  alert   — new alert session / update
  metrics — live throughput
  eval    — live precision/recall vs simulator ground truth
  event   — engine lifecycle events (warmup, retrain, drift)
"""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager

import redis.asyncio as redis
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from db import recent_alerts, stats
from eval import Evaluator

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:16379")
DATABASE_URL = os.environ.get("DATABASE_URL",
                              "postgresql://diode:diode@localhost:5433/diode")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.redis = redis.from_url(REDIS_URL, decode_responses=True,
                                     socket_timeout=None)
    await app.state.redis.ping()
    app.state.eval = Evaluator(app.state.redis, DATABASE_URL)
    await app.state.eval.catch_up()
    tasks = [
        asyncio.create_task(app.state.eval.poll()),
        asyncio.create_task(_relay_loop(app)),
    ]
    yield
    for t in tasks:
        t.cancel()
    await app.state.redis.aclose()


app = FastAPI(title="Diode Watch API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"])


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/alerts")
async def api_alerts(limit: int = 50, threat_class: str | None = None,
                     severity: str | None = None):
    return recent_alerts(limit, threat_class, severity)


@app.get("/api/stats")
async def api_stats():
    return stats()


@app.get("/api/eval")
async def api_eval():
    return app.state.eval.metrics()


@app.get("/api/drift")
async def api_drift():
    raw = await app.state.redis.get("diode:drift")
    if not raw:
        return {"drift": 0.0, "reason": "engine has not reported yet"}
    return json.loads(raw)


@app.post("/api/retrain")
async def api_retrain(model: str = "all"):
    await app.state.redis.publish("diode:commands",
                                  json.dumps({"cmd": "retrain", "model": model}))
    return {"scheduled": True, "model": model}


@app.post("/api/drift-check")
async def api_drift_check():
    """Ask the engine to compute PSI drift (used by n8n workflow)."""
    await app.state.redis.publish("diode:commands", json.dumps({"cmd": "drift"}))
    await asyncio.sleep(0.5)
    raw = await app.state.redis.get("diode:drift")
    return json.loads(raw) if raw else {"drift": 0.0, "reason": "no reply yet"}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    app.state.ws_clients.add(ws)
    try:
        await ws.send_text(json.dumps({
            "type": "snapshot",
            "alerts": recent_alerts(50),
            "stats": stats(),
            "eval": app.state.eval.metrics(),
        }))
        while True:
            await ws.receive_text()
    except (WebSocketDisconnect, Exception):
        app.state.ws_clients.discard(ws)


async def _relay_loop(app: FastAPI) -> None:
    app.state.ws_clients = set()
    pubsub = app.state.redis.pubsub()
    await pubsub.subscribe("diode:alerts", "diode:metrics", "diode:events")
    while True:
        try:
            msg = await pubsub.get_message(ignore_subscribe_messages=True,
                                           timeout=1.0)
            if msg is None:
                await _push_eval(app)
                continue
            channel = msg["channel"]
            if channel == "diode:alerts":
                alert = json.loads(msg["data"])
                app.state.eval.on_alert(alert)
                await _broadcast(app, {"type": "alert", "alert": alert})
            elif channel == "diode:metrics":
                await _broadcast(app, {"type": "metrics",
                                       **(json.loads(msg["data"]))})
            elif channel == "diode:events":
                await _broadcast(app, {"type": "event",
                                       **(json.loads(msg["data"]))})
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print(f"[relay] {exc}")
            await asyncio.sleep(1)


async def _push_eval(app: FastAPI) -> None:
    m = app.state.eval.metrics()
    if m["alert_sessions"] or m["truth_flows_seen"]:
        await _broadcast(app, {"type": "eval", **m})


async def _broadcast(app: FastAPI, payload: dict) -> None:
    text = json.dumps(payload)
    clients = [ws for ws in app.state.ws_clients]
    for ws in clients:
        try:
            await ws.send_text(text)
        except Exception:
            app.state.ws_clients.discard(ws)
