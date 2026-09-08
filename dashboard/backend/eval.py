"""Live ground-truth evaluation.

The simulator publishes attack flows to a separate truth stream
(flow_id -> label/class/key) that the detection path never sees. The
evaluator matches alert *sessions* against attack *episodes* and maintains
per-class precision / recall / F1 in real time.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field

EPISODE_GAP = 90.0       # sim-seconds between consecutive flows of one campaign
EPISODE_GRACE = 120.0    # sim-seconds after episode end before counting it as FN
ALERT_MATCH_WINDOW = 15.0

DDOS_CLASSES = {"DDOS_SYN_FLOOD", "DDOS_UDP_AMPLIFICATION", "DDOS_VOLUMETRIC",
                "DDOS_ANOMALY"}


@dataclass
class Episode:
    cls: str
    key: str
    start_ts: float
    last_ts: float
    flow_ids: set[str] = field(default_factory=set)
    alerted: bool = False      # at least one alert overlapped this campaign
    fn_claimed: bool = False   # already counted as a missed campaign
    seeded: bool = False       # replayed from history at startup (not counted as FN)
    finalized: bool = False


class Evaluator:
    def __init__(self, redis, dsn: str):
        self.redis = redis
        self.dsn = dsn
        self.episodes: dict[tuple[str, str], Episode] = {}
        self.finalized: list[Episode] = []
        self.alert_sessions: dict[str, str] = {}      # alert_id -> cls
        self.tp: dict[str, int] = {}
        self.fp: dict[str, int] = {}
        self.fn: dict[str, int] = {}
        self.total_episodes: dict[str, int] = {}
        self.max_ts = 0.0
        self.truth_seen = 0
        self.last_id = "0-0"

    # ------------------------------------------------------------ truth feed
    async def catch_up(self) -> None:
        while True:
            res = await self.redis.xread({TRUTH_STREAM: self.last_id}, count=10000,
                                         block=1000)
            if not res:
                return
            for _, messages in res:
                for mid, fields in messages:
                    if mid > self.last_id:
                        self.last_id = mid
                    self._add_truth(fields, seeded=True)
            if len(res[0][1]) < 10000:
                return

    async def poll(self) -> None:
        while True:
            try:
                res = await self.redis.xread({TRUTH_STREAM: self.last_id},
                                             count=10000, block=2000)
                for _, messages in res:
                    for mid, fields in messages:
                        if mid > self.last_id:
                            self.last_id = mid
                        self._add_truth(fields)
                await self._reap()
            except Exception as exc:
                print(f"[eval] truth poll error: {exc}")
                await asyncio.sleep(2)

    def _add_truth(self, fields: dict, seeded: bool = False) -> None:
        try:
            ts = float(fields["ts"])
            cls = fields["class"]
            key = fields["key"]
            flow_id = fields["flow_id"]
        except (KeyError, ValueError):
            return
        self.truth_seen += 1
        self.max_ts = max(self.max_ts, ts)
        k = (cls, key)
        ep = self.episodes.get(k)
        if ep and ts - ep.last_ts <= EPISODE_GAP:
            ep.last_ts = ts
            ep.flow_ids.add(flow_id)
            ep.seeded = ep.seeded or seeded
        else:
            if ep:
                ep.finalized = True
                self.finalized.append(ep)
                if len(self.finalized) > 5000:
                    self.finalized = self.finalized[-5000:]
            self.total_episodes[cls] = self.total_episodes.get(cls, 0) + 1
            self.episodes[k] = Episode(cls, key, ts, ts, {flow_id}, seeded=seeded)

    # ------------------------------------------------------------ alert match
    def on_alert(self, alert: dict) -> None:
        """Called for every alert session (occurrences == 1 message).

        An alert that overlaps a real campaign is a hit (the first alert to
        cover a campaign counts as TP; repeat alerts on an already-covered
        campaign are deduplicated). An alert that overlaps no campaign is FP.
        """
        aid = alert.get("alert_id", "")
        if aid in self.alert_sessions:
            return
        cls = alert["threat_class"]
        self.alert_sessions[aid] = cls
        self.max_ts = max(self.max_ts, float(alert.get("ts", 0)))
        flow_id = alert.get("flow_id")
        key = alert.get("key", "")
        ts = float(alert.get("ts", 0))

        window = ALERT_MATCH_WINDOW + EPISODE_GAP
        overlaps = [
            ep for ep in self._all_episodes()
            if _cls_matches(ep.cls, cls)
            and (flow_id in ep.flow_ids or key == ep.key)
            and ep.start_ts - window <= ts <= ep.last_ts + window
        ]
        if not overlaps:
            self.fp[cls] = self.fp.get(cls, 0) + 1
            return
        if any(not ep.alerted for ep in overlaps):
            self.tp[cls] = self.tp.get(cls, 0) + 1
        for ep in overlaps:
            ep.alerted = True

    def _all_episodes(self) -> list[Episode]:
        return [*self.finalized, *self.episodes.values()]

    async def _reap(self) -> None:
        """Finalize stale open episodes; count FNs once grace expires."""
        for k, ep in list(self.episodes.items()):
            if self.max_ts - ep.last_ts > EPISODE_GRACE:
                ep.finalized = True
                self.finalized.append(ep)
                del self.episodes[k]
        for ep in self.finalized:
            self._count_fn(ep)

    def _count_fn(self, ep: Episode) -> None:
        if ep.alerted or ep.seeded or ep.fn_claimed:
            return
        if self.max_ts - ep.last_ts <= EPISODE_GRACE:
            return
        ep.fn_claimed = True
        self.fn[ep.cls] = self.fn.get(ep.cls, 0) + 1

    def metrics(self) -> dict:
        per_class = {}
        for cls in sorted(set(self.tp) | set(self.fp) | set(self.fn)):
            tp, fp, fn = self.tp.get(cls, 0), self.fp.get(cls, 0), self.fn.get(cls, 0)
            prec = tp / max(1, tp + fp)
            rec = tp / max(1, tp + fn)
            per_class[cls] = {
                "tp": tp, "fp": fp, "fn": fn,
                "precision": round(prec, 3),
                "recall": round(rec, 3),
                "f1": round(2 * prec * rec / max(1e-9, prec + rec), 3),
                "episodes": self.total_episodes.get(cls, 0),
            }
        ttp = sum(self.tp.values())
        tfp = sum(self.fp.values())
        tfn = sum(self.fn.values())
        prec = ttp / max(1, ttp + tfp)
        rec = ttp / max(1, ttp + tfn)
        return {
            "per_class": per_class,
            "overall": {
                "precision": round(prec, 3), "recall": round(rec, 3),
                "f1": round(2 * prec * rec / max(1e-9, prec + rec), 3),
                "tp": ttp, "fp": tfp, "fn": tfn,
            },
            "truth_flows_seen": self.truth_seen,
            "alert_sessions": len(self.alert_sessions),
        }


def _cls_matches(truth_cls: str, alert_cls: str) -> bool:
    if truth_cls in DDOS_CLASSES and alert_cls in DDOS_CLASSES:
        return True
    return truth_cls == alert_cls


TRUTH_STREAM = "diode:ground_truth"
