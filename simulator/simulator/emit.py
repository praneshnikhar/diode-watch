"""Redis Streams emitter: flow records + a separate ground-truth stream."""

from __future__ import annotations

import json
import time

import redis.asyncio as redis

FLOWS_STREAM = "diode:flows"
TRUTH_STREAM = "diode:ground_truth"


class Emitter:
    def __init__(self, client: redis.Redis):
        self.client = client
        self.emitted = 0
        self.attack_flows = 0

    @classmethod
    async def connect(cls, url: str) -> "Emitter":
        client = redis.from_url(url, decode_responses=True)
        await client.ping()
        return cls(client)

    async def emit_flow(self, flow: dict, label: str | None = None) -> None:
        self.emitted += 1
        await self.client.xadd(FLOWS_STREAM, {"f": json.dumps(flow)}, maxlen=2_000_000)
        if label:
            self.attack_flows += 1
            await self.client.xadd(TRUTH_STREAM, {
                "flow_id": flow["flow_id"],
                "ts": flow["ts"],
                "label": label,
                "class": _CLASS_OF.get(label, "UNKNOWN"),
                "key": _key_of(label, flow),
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
            }, maxlen=2_000_000)


def _key_of(label: str, flow: dict) -> str:
    if label == "exfil":
        return f'{flow["src_ip"]}:{flow["dst_ip"]}'
    if label.startswith("ddos_"):
        return flow["dst_ip"]
    return flow["src_ip"]


_CLASS_OF = {
    "ddos_syn_flood": "DDOS_SYN_FLOOD",
    "ddos_udp_amplification": "DDOS_UDP_AMPLIFICATION",
    "c2_beacon": "C2_BEACON",
    "dga": "DGA_DOMAIN",
    "dns_tunnel": "DNS_TUNNEL",
    "tls_malware": "TLS_MALWARE",
    "port_scan": "RECON_SCAN",
    "exfil": "DATA_EXFIL",
}
