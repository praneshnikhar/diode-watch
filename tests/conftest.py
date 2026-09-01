"""Shared test harness: a minimal Context with stub metrics/redis and a
no-op AlertManager publish path (no Redis/DB required for unit tests)."""

from __future__ import annotations

import queue
from unittest.mock import MagicMock

import pytest

from engine.engine.alerts import AlertManager
from engine.engine.config import Config
from engine.engine.context import Context
from engine.engine.dga_model import DgaClassifier
from engine.engine.models import UnsupervisedModels
from engine.engine.schema import Flow
from engine.engine.windows import WindowStore


def make_flow(ts=1000.0, src="10.0.1.10", dst="203.0.113.5", sport=40000,
              dport=443, proto="tcp", packets=10, bytes_out=1000, bytes_in=9000,
              duration=1.0, flags=None, dns=None, tls=None, flow_id=None):
    return Flow(
        ts=ts, flow_id=flow_id or f"f{ts}", src_ip=src, dst_ip=dst,
        src_port=sport, dst_port=dport, proto=proto, packets=packets,
        bytes_out=bytes_out, bytes_in=bytes_in, duration=duration,
        flags=flags or [], dns=dns, tls=tls,
    )


@pytest.fixture
def ctx():
    metrics = MagicMock()
    metrics.alerts.labels.return_value.inc = MagicMock()
    metrics.flows = MagicMock()
    metrics.retrains = MagicMock()
    metrics.window_keys = MagicMock()
    metrics.throughput = MagicMock()
    metrics.alert_rate = MagicMock()
    metrics.drift = MagicMock()
    cfg = Config(redis_url="redis://nowhere", database_url="postgresql://nowhere")
    manager = AlertManager(cfg, queue.Queue(), None, metrics)

    async def _nop(*a, **k):
        return None

    manager._publish = _nop  # no async publish in unit tests
    c = Context(cfg, WindowStore(), UnsupervisedModels(),
                DgaClassifier(source="heuristic"), manager, None, metrics)
    return c
