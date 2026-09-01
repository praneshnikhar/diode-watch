"""Sliding-window state store keyed by arbitrary strings.

All window arithmetic uses *flow timestamps* (simulation time), so detection
behaviour is independent of wall-clock playback speed.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

T = TypeVar("T")


@dataclass
class Entry(Generic[T]):
    ts: float
    value: T


class WindowStore:
    def __init__(self) -> None:
        self._data: dict[str, deque[Entry[Any]]] = defaultdict(deque)

    def push(self, key: str, ts: float, value: Any, age: float = 3600.0,
             maxlen: int = 100_000) -> None:
        dq = self._data[key]
        cutoff = ts - age
        while dq and dq[0].ts < cutoff:
            dq.popleft()
        dq.append(Entry(ts, value))
        if len(dq) > maxlen:
            dq.popleft()

    def window(self, key: str, ts: float, age: float) -> list[Entry[Any]]:
        dq = self._data[key]
        cutoff = ts - age
        while dq and dq[0].ts < cutoff:
            dq.popleft()
        return list(dq)

    def __len__(self) -> int:
        return len(self._data)
