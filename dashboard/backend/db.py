"""TimescaleDB read helpers for the dashboard API."""

from __future__ import annotations

import os

import psycopg
from psycopg.rows import dict_row

DSN = os.environ.get("DATABASE_URL", "postgresql://diode:diode@localhost:5433/diode")


def connect():
    return psycopg.connect(DSN, row_factory=dict_row, autocommit=True)


def recent_alerts(limit: int = 50, threat_class: str | None = None,
                  severity: str | None = None) -> list[dict]:
    sql = """
        SELECT time, alert_id, threat_class, severity, confidence, key, flow_id,
               src_ip, dst_ip, src_port, dst_port, proto, evidence, explanation,
               occurrences
        FROM alerts
    """
    conds, params = [], []
    if threat_class:
        conds.append("threat_class = %s")
        params.append(threat_class)
    if severity:
        conds.append("severity = %s")
        params.append(severity)
    if conds:
        sql += " WHERE " + " AND ".join(conds)
    sql += " ORDER BY time DESC LIMIT %s"
    params.append(limit)
    with connect() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    for r in rows:
        r["time"] = r["time"].isoformat()
    return rows


def stats(since_sim_seconds: float = 3600.0) -> dict:
    out: dict = {}
    with connect() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT threat_class, severity, count(*) AS n
            FROM alerts
            WHERE time > to_timestamp((SELECT max(time) FROM alerts) - %s)
              AND occurrences = 1
            GROUP BY threat_class, severity
        """, (since_sim_seconds,))
        out["by_class_severity"] = cur.fetchall()
        cur.execute("SELECT count(*) AS n FROM alerts")
        out["total_alerts"] = cur.fetchone()["n"]
        cur.execute("""
            SELECT count(DISTINCT alert_id) AS sessions
            FROM alerts WHERE time > to_timestamp((SELECT max(time) FROM alerts) - %s)
        """, (since_sim_seconds,))
        out["sessions"] = cur.fetchone()["sessions"]
    return out
