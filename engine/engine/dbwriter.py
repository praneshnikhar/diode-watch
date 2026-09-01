"""Background writer thread: batched inserts into TimescaleDB."""

from __future__ import annotations

import queue
import threading
import time
from datetime import datetime, timezone

import psycopg
from psycopg.types.json import Jsonb

SCHEMA = """
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE TABLE IF NOT EXISTS alerts (
    time          TIMESTAMPTZ NOT NULL,
    alert_id      TEXT NOT NULL,
    threat_class  TEXT NOT NULL,
    severity      TEXT NOT NULL,
    confidence    DOUBLE PRECISION,
    key           TEXT,
    flow_id       TEXT,
    src_ip        TEXT,
    dst_ip        TEXT,
    src_port      INTEGER,
    dst_port      INTEGER,
    proto         TEXT,
    evidence      JSONB,
    explanation   TEXT,
    occurrences   INTEGER DEFAULT 1
);
SELECT create_hypertable('alerts', 'time', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS idx_alerts_class_time ON alerts (threat_class, time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_sev_time   ON alerts (severity, time DESC);
"""

INSERT = """
INSERT INTO alerts (time, alert_id, threat_class, severity, confidence, key,
                    flow_id, src_ip, dst_ip, src_port, dst_port, proto,
                    evidence, explanation, occurrences)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


class DbWriter(threading.Thread):
    def __init__(self, dsn: str, q: queue.Queue):
        super().__init__(daemon=True, name="db-writer")
        self.dsn = dsn
        self.q = q
        self.written = 0

    def run(self) -> None:
        conn = None
        while conn is None:
            try:
                conn = psycopg.connect(self.dsn, autocommit=True)
                conn.execute(SCHEMA)
            except Exception as exc:
                print(f"[db] waiting for database ({exc})")
                time.sleep(3)
        print("[db] connected, schema ready")
        while True:
            batch = [self.q.get()]
            try:
                while len(batch) < 200:
                    batch.append(self.q.get_nowait())
            except queue.Empty:
                pass
            rows = []
            for a in batch:
                if a is None:
                    return
                rows.append((
                    datetime.fromtimestamp(a["ts"], tz=timezone.utc),
                    a["alert_id"], a["threat_class"], a["severity"],
                    a["confidence"], a["key"], a["flow_id"], a["src_ip"],
                    a["dst_ip"], a["src_port"], a["dst_port"], a["proto"],
                    Jsonb(a["evidence"]), a["explanation"], a["occurrences"],
                ))
            try:
                with conn.cursor() as cur:
                    cur.executemany(INSERT, rows)
                self.written += len(rows)
            except Exception as exc:
                print(f"[db] insert failed: {exc}")
                for a in batch:
                    self.q.put(a)
                time.sleep(2)
