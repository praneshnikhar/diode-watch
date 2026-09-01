"""Redis Streams emitter: flow records + a separate ground-truth stream."""

from __future__ import annotations

import json
import time

import redis

FLOWS_STREAM = "diode:flows"
TRUTH_STREAM = "diode:ground_truth"


class Emitter:
    def __init__(self, client: redis.Redis):
        self.client = client
        self.emitted = 0
        self.attack_flows = 0
        self._buffer: list[tuple[dict, str | None]] = []

    @classmethod
    async def connect(cls, url: str) -> "Emitter":
        # socket_timeout=None: the simulator only ever issues short, non-
        # blocking writes; a client-side read timeout would abort them under
        # load (redis-py >=8 defaults it to 5s).
        client = redis.from_url(url, decode_responses=True, socket_timeout=None)
        client.ping()
        return cls(client)

    def emit_flow(self, flow: dict, label: str | None = None) -> None:
        """Buffer one flow record (and, for attack flows, its ground-truth
        label). Synchronous on purpose: the scenario `tick` methods are
        synchronous and call this directly, so an async client would create
        un-awaited coroutines and drop every flow. Records are written in
        batches by `flush()` to avoid a network round-trip per flow."""
        self.emitted += 1
        if label:
            self.attack_flows += 1
        self._buffer.append((flow, label))

    def flush(self) -> None:
        """Write all buffered flows (and truth labels) in one pipeline."""
        if not self._buffer:
            return
        pipe = self.client.pipeline(transaction=False)
        for flow, _label in self._buffer:
            pipe.xadd(FLOWS_STREAM, {"f": json.dumps(flow)}, maxlen=2_000_000)
        for flow, label in self._buffer:
            if label:
                pipe.xadd(TRUTH_STREAM, {
                    "flow_id": flow["flow_id"],
                    "ts": flow["ts"],
                    "label": label,
                    "class": _CLASS_OF.get(label, "UNKNOWN"),
                    "key": _key_of(label, flow),
                    "src_ip": flow["src_ip"],
                    "dst_ip": flow["dst_ip"],
                }, maxlen=2_000_000)
        pipe.execute()
        self._buffer = []


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
