from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class Config:
    redis_url: str = os.environ.get("REDIS_URL", "redis://localhost:16379")
    database_url: str = os.environ.get(
        "DATABASE_URL", "postgresql://diode:diode@localhost:5433/diode")
    n8n_webhook_url: str = os.environ.get("N8N_WEBHOOK_URL", "")
    warmup_sim_seconds: float = float(os.environ.get("WARMUP_SIM_SECONDS", "180"))
    warmup_wall_cap: float = 90.0
    metrics_port: int = int(os.environ.get("METRICS_PORT", "9100"))
    throughput_target: float = float(os.environ.get("THROUGHPUT_TARGET", "2000"))

    @classmethod
    def from_env(cls) -> "Config":
        return cls()
