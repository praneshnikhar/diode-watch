"""Simulator entrypoint.

Simulated time runs `speed` times faster than wall-clock so a full demo of
benign traffic + every attack class fits into a few real minutes.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import time

from .emit import Emitter
from .scenarios import Orchestrator


async def run(args: argparse.Namespace) -> None:
    emitter = await Emitter.connect(args.redis)
    orch = Orchestrator(seed=args.seed, flows_per_sec=args.flows_per_sec)
    print(f"[simulator] connected to {args.redis} | speed={args.speed}x | "
          f"target={args.flows_per_sec} flows/sim-sec | warmup={orch.WARMUP_SIM} sim-sec")

    sim_ts = 0.0
    wall_start = time.monotonic()
    last_log = wall_start
    step = 0.05  # real seconds per tick
    try:
        while True:
            if args.duration and wall_start + args.duration < time.monotonic():
                break
            sim_dt = step * args.speed
            orch.tick(sim_ts, sim_dt, emitter.emit_flow)
            emitter.flush()
            sim_ts += sim_dt
            now = time.monotonic()
            if now - last_log >= 10:
                last_log = now
                attacks = orch.attack_emitted
                print(f"[simulator] sim_t={sim_ts:8.0f}s | flows={emitter.emitted:>8} "
                      f"({emitter.emitted / max(1, now - wall_start):7.0f}/s real) | "
                      f"attacks={emitter.attack_flows:>7} | active={sorted(attacks) or 'none'}")
            await asyncio.sleep(step)
    except asyncio.CancelledError:
        pass
    finally:
        print("[simulator] stopped")


def main() -> None:
    p = argparse.ArgumentParser(description="Diode Watch synthetic traffic simulator")
    p.add_argument("--redis", default=os.environ.get("REDIS_URL", "redis://localhost:16379"))
    p.add_argument("--speed", type=float, default=float(os.environ.get("SPEED", "60")))
    p.add_argument("--flows-per-sec", type=float,
                   default=float(os.environ.get("FLOWS_PER_SEC", "800")))
    p.add_argument("--seed", type=int, default=int(os.environ.get("SCENARIO_SEED", "42")))
    p.add_argument("--duration", type=float, default=0.0,
                   help="real seconds to run (0 = forever)")
    asyncio.run(run(p.parse_args()))


if __name__ == "__main__":
    main()
