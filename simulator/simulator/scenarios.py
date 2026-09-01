"""Attack + benign scenario generators with ground-truth labels."""

from __future__ import annotations

import random

from ml import dga_domains

from . import flowlib as fl

DGA_QNAMES = [q for q in
              ("A",) * 60 + ("AAAA",) * 15 + ("NS",) * 10 + ("CNAME",) * 10 + ("MX",) * 5]


class Scenario:
    """Base class. `tick` is called once per simulation step."""

    name = "base"
    label = None          # ground-truth label attached to emitted flows (None = benign)
    gt_class = None       # alert class this attack should produce
    gt_key = "src"        # eval matching key: "src" | "dst" | "src_dst"
    attack = False

    def __init__(self, rng: random.Random, flows_per_sec: float):
        self.rng = rng
        self.fps = flows_per_sec
        self._next = 0.0
        self.emitted = 0

    def tick(self, sim_ts: float, sim_dt: float, emit) -> None:
        raise NotImplementedError

    def _emit(self, flow: dict, emit) -> None:
        self.emitted += 1
        emit(flow, self.label)


class BenignTraffic(Scenario):
    name = "benign"

    def __init__(self, rng: random.Random, flows_per_sec: float):
        super().__init__(rng, flows_per_sec)
        self.rate = max(10.0, flows_per_sec * 0.75)

    def tick(self, sim_ts: float, sim_dt: float, emit) -> None:
        if self._next == 0.0:
            self._next = sim_ts + self.rng.expovariate(self.rate)
        while self._next <= sim_ts:
            self._next += self.rng.expovariate(self.rate)
            self._emit(self._benign_flow(sim_ts), emit)

    def _benign_flow(self, ts: float) -> dict:
        r = self.rng.random()
        src = self.rng.choice(fl.LAN_HOSTS)
        if r < 0.55:  # web
            dst = self.rng.choice(fl.WEB_SERVERS)
            port = self.rng.choice([443, 443, 443, 80, 8080])
            tls = None
            if port == 443 and self.rng.random() < 0.7:
                tls = {
                    "ja3": fl.benign_ja3(self.rng),
                    "client_hello_size": self.rng.randint(280, 420),
                    "server_hello_size": self.rng.randint(90, 220),
                    "cert_depth": self.rng.choice([1, 2, 2, 3]),
                    "handshake_packets": self.rng.randint(6, 12),
                    "tls_version": self.rng.choice(["TLS1.2", "TLS1.3", "TLS1.3"]),
                    "cipher_entropy": round(self.rng.uniform(2.8, 4.2), 2),
                }
            return fl.make_flow(
                ts, src, dst, fl.ephem_port(self.rng), port, "tcp",
                self.rng.randint(8, 90), self.rng.randint(1000, 9000),
                self.rng.randint(8000, 120000), round(self.rng.uniform(0.5, 30), 2),
                ["PSH", "ACK"], tls=tls,
            )
        if r < 0.75:  # dns
            dst = self.rng.choice(fl.DNS_RESOLVERS)
            return fl.make_flow(
                ts, src, dst, fl.ephem_port(self.rng), 53, "udp",
                self.rng.randint(1, 2), self.rng.randint(40, 90),
                self.rng.randint(60, 300), round(self.rng.uniform(0.01, 0.3), 3),
                dns={"qname": fl.legit_domain(self.rng), "qtype": self.rng.choice(DGA_QNAMES)},
            )
        if r < 0.83:  # quic
            dst = self.rng.choice(fl.WEB_SERVERS)
            return fl.make_flow(
                ts, src, dst, fl.ephem_port(self.rng), 443, "udp",
                self.rng.randint(6, 40), self.rng.randint(1500, 8000),
                self.rng.randint(8000, 40000), round(self.rng.uniform(1, 20), 2),
                tls={"quic": True, "handshake_packets": self.rng.randint(2, 6)},
            )
        if r < 0.88:  # ntp
            dst = self.rng.choice(fl.NTP_SERVERS)
            return fl.make_flow(
                ts, src, dst, 123, 123, "udp",
                self.rng.randint(1, 2), 48, 48, 0.01,
            )
        if r < 0.92:  # icmp
            dst = self.rng.choice(fl.WEB_SERVERS)
            return fl.make_flow(
                ts, src, dst, 0, 0, "icmp",
                self.rng.randint(1, 4), self.rng.randint(64, 600), 0, 0.0,
            )
        # internal lan traffic
        dst = self.rng.choice(fl.LAN_HOSTS)
        return fl.make_flow(
            ts, src, dst, fl.ephem_port(self.rng), self.rng.choice([22, 445, 8080, 9100]),
            "tcp", self.rng.randint(4, 40), self.rng.randint(500, 20000),
            self.rng.randint(500, 20000), round(self.rng.uniform(0.1, 15), 2),
            ["PSH", "ACK"],
        )


class SynFloodEp(Scenario):
    name = "syn_flood"
    label = "ddos_syn_flood"
    gt_class = "DDOS_SYN_FLOOD"
    gt_key = "dst"
    attack = True

    def __init__(self, rng, fps, rate=3000.0):
        super().__init__(rng, fps)
        self.rate = rate

    def tick(self, sim_ts, sim_dt, emit):
        if self._next == 0.0:
            self._next = sim_ts
        while self._next <= sim_ts:
            self._next += self.rng.expovariate(self.rate)
            self._emit(fl.make_flow(
                sim_ts, self.rng.choice(fl.SPOOF_POOL), fl.FLOOD_VICTIM,
                fl.ephem_port(self.rng), self.rng.choice([80, 443, 22]), "tcp",
                1, 0, 0, 0.0, ["SYN"],
            ), emit)


class UdpAmpEp(Scenario):
    name = "udp_amp"
    label = "ddos_udp_amplification"
    gt_class = "DDOS_UDP_AMPLIFICATION"
    gt_key = "dst"
    attack = True

    def __init__(self, rng, fps, rate=1000.0):
        super().__init__(rng, fps)
        self.rate = rate

    def tick(self, sim_ts, sim_dt, emit):
        if self._next == 0.0:
            self._next = sim_ts
        while self._next <= sim_ts:
            self._next += self.rng.expovariate(self.rate)
            self._emit(fl.make_flow(
                sim_ts, self.rng.choice(fl.SPOOF_POOL), fl.REFLECTOR,
                fl.ephem_port(self.rng), 53, "udp",
                1, 64, self.rng.randint(4096, 8192), 0.01,
            ), emit)


class C2BeaconScenario(Scenario):
    name = "c2_beacon"
    label = "c2_beacon"
    gt_class = "C2_BEACON"
    attack = True

    def __init__(self, rng, fps):
        super().__init__(rng, fps)
        self.hosts: dict[str, float] = {}

    def tick(self, sim_ts, sim_dt, emit):
        if not self.hosts:
            for h in fl.INFECTED:
                self.hosts[h] = sim_ts + self.rng.uniform(0, 60)
        for host, due in list(self.hosts.items()):
            while due <= sim_ts:
                self.hosts[host] = due + max(10.0, self.rng.gauss(60, 1.5))
                self._emit(fl.make_flow(
                    sim_ts, host, fl.C2_HTTP, fl.ephem_port(self.rng), 443, "tcp",
                    self.rng.randint(3, 8), self.rng.randint(200, 600),
                    self.rng.randint(800, 3000), round(self.rng.uniform(0.3, 1.5), 2),
                    ["PSH", "ACK"],
                ), emit)


class DgaScenario(Scenario):
    name = "dga"
    label = "dga"
    gt_class = "DGA_DOMAIN"
    attack = True

    def __init__(self, rng, fps):
        super().__init__(rng, fps)
        self._rate = 1.0 / 25.0   # one DGA query every ~25s baseline
        self.burst = False

    def tick(self, sim_ts, sim_dt, emit):
        if self._next == 0.0:
            self._next = sim_ts + self.rng.expovariate(self._rate)
        while self._next <= sim_ts:
            self._next += self.rng.expovariate(self._rate)
            src = self.rng.choice(fl.INFECTED[:2])
            self._emit(fl.make_flow(
                sim_ts, src, self.rng.choice(fl.DNS_RESOLVERS),
                fl.ephem_port(self.rng), 53, "udp",
                1, self.rng.randint(40, 90), self.rng.randint(60, 300), 0.02,
                dns={"qname": dga_domains.generate_dga_domain(self.rng),
                     "qtype": self.rng.choice(["A", "A", "A", "AAAA", "NS"])},
            ), emit)


def tunnel_qname(rng: random.Random) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    labels = ["".join(rng.choice(alphabet) for _ in range(rng.randint(9, 14)))
              for _ in range(rng.randint(3, 4))]
    return ".".join(labels) + ".dns.tun-example.net"


class DnsTunnelEp(Scenario):
    name = "dns_tunnel"
    label = "dns_tunnel"
    gt_class = "DNS_TUNNEL"
    attack = True

    def __init__(self, rng, fps, rate=1.0 / 2.5):
        super().__init__(rng, fps)
        self.rate = rate

    def tick(self, sim_ts, sim_dt, emit):
        if self._next == 0.0:
            self._next = sim_ts
        while self._next <= sim_ts:
            self._next += self.rng.expovariate(self.rate)
            self._emit(fl.make_flow(
                sim_ts, fl.INFECTED[2], fl.TUNNEL_NS, fl.ephem_port(self.rng), 53, "udp",
                2, self.rng.randint(60, 120), self.rng.randint(1500, 3000), 0.05,
                dns={"qname": tunnel_qname(self.rng),
                     "qtype": self.rng.choice(["TXT", "TXT", "TXT", "NULL", "A"])},
            ), emit)


class TlsMalwareEp(Scenario):
    name = "tls_malware"
    label = "tls_malware"
    gt_class = "TLS_MALWARE"
    attack = True

    def __init__(self, rng, fps, interval=45.0):
        super().__init__(rng, fps)
        self.interval = interval

    def tick(self, sim_ts, sim_dt, emit):
        if self._next == 0.0:
            self._next = sim_ts
        while self._next <= sim_ts:
            self._next += self.rng.uniform(self.interval * 0.8, self.interval * 1.2)
            src = fl.INFECTED[0]
            sess = self.rng.uniform(0, 99999)
            n = self.rng.randint(4, 6)
            for i in range(n):
                tls = {
                    "ja3": fl.bad_ja3(self.rng),
                    "client_hello_size": 517,
                    "server_hello_size": 92,
                    "cert_depth": 1,
                    "handshake_packets": self.rng.randint(8, 14) if i == 0 else 2,
                    "tls_version": "TLS1.2",
                    "cipher_entropy": round(self.rng.uniform(1.4, 2.2), 2),
                }
                self._emit(fl.make_flow(
                    sim_ts, src, fl.C2_TLS, fl.ephem_port(self.rng), 443, "tcp",
                    tls["handshake_packets"] + self.rng.randint(0, 4),
                    self.rng.randint(400, 1500), self.rng.randint(200, 900),
                    round(self.rng.uniform(0.1, 2.5), 2), ["PSH", "ACK"], tls=tls,
                ), emit)


class PortScanVep(Scenario):
    name = "port_scan_vertical"
    label = "port_scan"
    gt_class = "RECON_SCAN"
    attack = True

    def __init__(self, rng, fps):
        super().__init__(rng, fps)
        self.port = 1

    def tick(self, sim_ts, sim_dt, emit):
        if self._next == 0.0:
            self._next = sim_ts
        while self._next <= sim_ts and self.port <= 6000:
            self._next += self.rng.uniform(0.03, 0.08)
            p = self.port
            self.port += 1
            if self.port == 1025:
                self.port = 20000
            self._emit(fl.make_flow(
                sim_ts, fl.SCANNER, fl.SCAN_VERTICAL_TARGET,
                fl.ephem_port(self.rng), p, "tcp", 1, 0, 0, 0.0, ["SYN"],
            ), emit)


class PortScanHep(Scenario):
    name = "port_scan_horizontal"
    label = "port_scan"
    gt_class = "RECON_SCAN"
    attack = True

    def __init__(self, rng, fps):
        super().__init__(rng, fps)
        self.hosts = iter([])
        self.n = 0

    def tick(self, sim_ts, sim_dt, emit):
        if self._next == 0.0:
            self._next = sim_ts
        while self._next <= sim_ts and self.n < 200:
            self._next += self.rng.uniform(0.1, 0.2)
            dst = fl.SCAN_HORIZONTAL_RANGE[self.n]
            self.n += 1
            self._emit(fl.make_flow(
                sim_ts, fl.SCANNER, dst, fl.ephem_port(self.rng), 445, "tcp",
                1, 0, 0, 0.0, ["SYN"],
            ), emit)


class ExfilEp(Scenario):
    name = "exfil"
    label = "exfil"
    gt_class = "DATA_EXFIL"
    gt_key = "src_dst"
    attack = True

    def __init__(self, rng, fps, rate=1.0 / 6.0):
        super().__init__(rng, fps)
        self.rate = rate

    def tick(self, sim_ts, sim_dt, emit):
        if self._next == 0.0:
            self._next = sim_ts
        while self._next <= sim_ts:
            self._next += self.rng.expovariate(self.rate)
            self._emit(fl.make_flow(
                sim_ts, fl.INFECTED[1], fl.EXFIL_DST, fl.ephem_port(self.rng), 443, "tcp",
                self.rng.randint(20, 80), self.rng.randint(25000, 60000),
                self.rng.randint(150, 400), round(self.rng.uniform(2, 6), 2),
                ["PSH", "ACK"],
            ), emit)


class Orchestrator:
    """Activates scenarios on a repeating schedule; benign traffic always on."""

    WARMUP_SIM = 300.0

    def __init__(self, seed: int = 42, flows_per_sec: float = 800.0):
        self.rng = random.Random(seed)
        self.fps = flows_per_sec
        self.benign = BenignTraffic(self.rng, flows_per_sec)
        self.schedule = [
            # (factory, start, duration, repeat_period)
            (SynFloodEp, 320, 60, 1800),
            (UdpAmpEp, 460, 45, 1800),
            (C2BeaconScenario, 380, float("inf"), None),
            (DgaScenario, 350, float("inf"), None),
            (DnsTunnelEp, 700, 180, 1800),
            (TlsMalwareEp, 900, 90, 1800),
            (PortScanVep, 500, 40, 2400),
            (PortScanHep, 545, 40, 2400),
            (ExfilEp, 1100, 300, 2400),
        ]
        self.active: list[Scenario] = []
        self.episodes: list[dict] = [
            {"factory": f, "start": s, "dur": d, "period": p, "scen": None}
            for f, s, d, p in self.schedule
        ]
        self.started = set()

    def tick(self, sim_ts: float, sim_dt: float, emit) -> None:
        for ep in self.episodes:
            if ep["scen"] is None and sim_ts >= ep["start"]:
                ep["scen"] = ep["factory"](self.rng, self.fps)
                self.active.append(ep["scen"])
            if ep["scen"] is not None and sim_ts >= ep["start"] + ep["dur"]:
                self.active.remove(ep["scen"])
                ep["scen"] = None
                if ep["period"]:
                    ep["start"] += ep["period"]
        self.benign.tick(sim_ts, sim_dt, emit)
        for scen in list(self.active):
            scen.tick(sim_ts, sim_dt, emit)

    @property
    def attack_emitted(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for ep in self.episodes:
            if ep["scen"] is not None:
                out[ep["scen"].name] = ep["scen"].emitted
        return out
