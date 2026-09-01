"""Shared helpers: IP pools, domains, JA3 fingerprints, flow record builder."""

from __future__ import annotations

import hashlib
import random
import uuid
from pathlib import Path

from ml.ja3_denylist import KNOWN_BAD_JA3

# --- IP pools (all in documentation ranges, no real addresses) -------------

LAN_HOSTS = [f"10.0.1.{i}" for i in range(2, 42)]          # benign internal users
INFECTED = ["10.0.1.50", "10.0.1.51", "10.0.1.52"]         # compromised hosts
SCANNER = "10.0.3.7"
FLOOD_VICTIM = "10.0.2.5"                                   # internal server under DDoS
SCAN_VERTICAL_TARGET = "10.0.2.6"
SCAN_HORIZONTAL_RANGE = [f"10.0.4.{i}" for i in range(1, 201)]

WEB_SERVERS = [f"203.0.113.{i}" for i in range(1, 61)]      # benign internet
DNS_RESOLVERS = ["203.0.113.201", "203.0.113.202"]
REFLECTOR = "203.0.113.53"                                  # UDP reflector
NTP_SERVERS = ["203.0.113.123", "203.0.113.124"]

C2_HTTP = "198.51.100.10"        # botnet C2 (beaconing)
TUNNEL_NS = "198.51.100.20"      # attacker DNS server (tunnelling)
C2_TLS = "198.51.100.30"         # malware-over-TLS C2
EXFIL_DST = "198.51.100.40"      # exfiltration receiver
SPOOF_POOL = [f"198.51.100.{i}" for i in range(100, 200)] + \
             [f"192.0.2.{i}" for i in range(1, 200)]

# --- TLS fingerprint material ----------------------------------------------

# Known-bad JA3 hashes are shared with the engine via ml.ja3_denylist.
BENIGN_JA3_POOL = [hashlib.md5(f"benign-{i}".encode()).hexdigest() for i in range(40)]


def _load_legit_domains() -> list[str]:
    for base in (Path(__file__).resolve().parents[2], Path.cwd(), Path("/app")):
        p = base / "ml" / "data" / "legit_domains.txt"
        if p.exists():
            return [ln.strip() for ln in p.read_text().splitlines() if ln.strip()]
    raise FileNotFoundError("ml/data/legit_domains.txt not found")


LEGIT_DOMAINS = _load_legit_domains()


def legit_domain(rng: random.Random) -> str:
    d = rng.choice(LEGIT_DOMAINS)
    if rng.random() < 0.3:
        d = f"{rng.choice(['www', 'api', 'cdn', 'mail', 'app', 'edge', 'static'])}.{d}"
    return d


def benign_ja3(rng: random.Random) -> str:
    return rng.choice(BENIGN_JA3_POOL)


def bad_ja3(rng: random.Random) -> str:
    return rng.choice(list(KNOWN_BAD_JA3))


def make_flow(
    ts: float,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    proto: str,
    packets: int,
    bytes_out: int,
    bytes_in: int,
    duration: float,
    flags: list[str] | None = None,
    dns: dict | None = None,
    tls: dict | None = None,
) -> dict:
    return {
        "ts": round(ts, 3),
        "flow_id": uuid.uuid4().hex,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto,
        "packets": packets,
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
        "duration": round(duration, 3),
        "flags": flags or [],
        "dns": dns,
        "tls": tls,
    }


def ephem_port(rng: random.Random) -> int:
    return rng.randint(32768, 60999)
