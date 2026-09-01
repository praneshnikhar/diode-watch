import numpy as np

from engine.engine.detectors.c2 import C2Detector, periodicity_score
from engine.engine.detectors.ddos import DdosDetector
from engine.engine.detectors.dga_dns import DgaDnsDetector
from engine.engine.detectors.exfil import ExfilDetector
from engine.engine.detectors.recon import ReconDetector
from engine.engine.detectors.tls_malware import TlsMalwareDetector

from conftest import make_flow


def _run(det, flows):
    out = []
    for f in flows:
        out.extend(det.process(f))
    return out


# ---------------------------------------------------------------- C2 beacons

def test_c2_detects_periodic_beacon(ctx):
    det = C2Detector(ctx)
    flows = [make_flow(ts=1000 + 60 * i, src="10.0.1.50", dst="198.51.100.10",
                       dport=443, packets=5, bytes_out=300, bytes_in=1500)
             for i in range(7)]
    alerts = _run(det, flows)
    assert any(a.threat_class == "C2_BEACON" for a in alerts)
    a = [x for x in alerts if x.threat_class == "C2_BEACON"][-1]
    assert a.evidence["inter_arrival_cv"] < 0.1


def test_c2_ignores_irregular_traffic(ctx):
    det = C2Detector(ctx)
    ts = [1000, 1017, 1101, 1190, 1355, 1520]
    alerts = _run(det, [make_flow(ts=t, src="10.0.1.10", dst="203.0.113.5",
                                  packets=5) for t in ts])
    assert alerts == []


def test_periodicity_score_periodic_vs_random():
    t = 1000 + 60 * np.arange(8)
    periodic = periodicity_score(t)
    t2 = np.cumsum(np.random.RandomState(0).exponential(40, 8)) + 1000
    random_ = periodicity_score(t2)
    assert periodic > 6.0
    assert random_ < periodic


# ------------------------------------------------------------------- DDoS

def test_ddos_syn_flood_spoofed_sources(ctx):
    det = DdosDetector(ctx)
    flows = [make_flow(ts=1000 + i * 0.01, src=f"198.51.100.{i % 150}",
                       dst="10.0.2.5", dport=80, packets=1, bytes_out=0,
                       bytes_in=0, flags=["SYN"]) for i in range(300)]
    alerts = _run(det, flows)
    classes = {a.threat_class for a in alerts}
    assert "DDOS_SYN_FLOOD" in classes


def test_ddos_udp_amplification(ctx):
    det = DdosDetector(ctx)
    flows = [make_flow(ts=1000 + i * 0.01, src=f"192.0.2.{i % 80}",
                       dst="10.0.2.5", dport=53, proto="udp", packets=1,
                       bytes_out=64, bytes_in=6000) for i in range(160)]
    alerts = _run(det, flows)
    classes = {a.threat_class for a in alerts}
    assert "DDOS_UDP_AMPLIFICATION" in classes


# --------------------------------------------------------------- DGA / DNS

def test_dga_heuristic_flags_random_domain(ctx):
    det = DgaDnsDetector(ctx)
    f = make_flow(proto="udp", dport=53,
                  dns={"qname": "xqjzvklrwmbpzq.xyz", "qtype": "A"})
    alerts = det.process(f)
    assert any(a.threat_class == "DGA_DOMAIN" for a in alerts)


def test_dga_ignores_legit_domain(ctx):
    det = DgaDnsDetector(ctx)
    f = make_flow(proto="udp", dport=53,
                  dns={"qname": "www.google.com", "qtype": "A"})
    assert det.process(f) == []


def test_dns_tunnel_long_high_entropy(ctx):
    det = DgaDnsDetector(ctx)
    qname = "k7f2a9x4q3b1m.zz8p2y6w5n3r.q1v9t8m4c2s7x.dns.tun-example.net"
    f = make_flow(proto="udp", dport=53, dns={"qname": qname, "qtype": "TXT"})
    alerts = det.process(f)
    assert any(a.threat_class == "DNS_TUNNEL" for a in alerts)


# --------------------------------------------------------------------- TLS

def test_tls_ja3_denylist(ctx):
    det = TlsMalwareDetector(ctx)
    f = make_flow(dport=443, tls={"ja3": "6734f37431670b3ab4292b8f60f29984",
                                  "client_hello_size": 517, "cipher_entropy": 1.8})
    alerts = det.process(f)
    assert any(a.threat_class == "TLS_MALWARE" and a.confidence >= 0.9
               for a in alerts)


def test_tls_benign_ja3_no_alert(ctx):
    det = TlsMalwareDetector(ctx)
    f = make_flow(dport=443, tls={"ja3": "9c9c4f99e7a2a8e97be0e8e1e1e1e1e1",
                                  "client_hello_size": 350,
                                  "server_hello_size": 150, "cert_depth": 2,
                                  "handshake_packets": 8, "cipher_entropy": 3.5})
    assert det.process(f) == []


# ------------------------------------------------------------------- recon

def test_recon_vertical_scan(ctx):
    det = ReconDetector(ctx)
    flows = [make_flow(ts=1000 + i * 0.05, src="10.0.3.7", dst="10.0.2.6",
                       dport=1 + i, packets=1, bytes_out=0, bytes_in=0,
                       flags=["SYN"]) for i in range(200)]
    alerts = _run(det, flows)
    assert any(a.threat_class == "RECON_SCAN" for a in alerts)


def test_recon_horizontal_scan(ctx):
    det = ReconDetector(ctx)
    flows = [make_flow(ts=1000 + i * 0.1, src="10.0.3.7", dst=f"10.0.4.{i}",
                       dport=445, packets=1, bytes_out=0, bytes_in=0,
                       flags=["SYN"]) for i in range(150)]
    alerts = _run(det, flows)
    assert any(a.threat_class == "RECON_SCAN" for a in alerts)


def test_recon_ignores_normal_traffic(ctx):
    det = ReconDetector(ctx)
    flows = [make_flow(ts=1000 + i, src="10.0.1.10", dst="203.0.113.5",
                       packets=20, bytes_out=1000, bytes_in=5000)
             for i in range(30)]
    assert _run(det, flows) == []


# ------------------------------------------------------------------- exfil

def test_exfil_asymmetric_ratio(ctx):
    det = ExfilDetector(ctx)
    flows = [make_flow(ts=1000 + i * 5, src="10.0.1.51", dst="198.51.100.40",
                       packets=40, bytes_out=40000, bytes_in=300)
             for i in range(5)]
    alerts = _run(det, flows)
    assert any(a.threat_class == "DATA_EXFIL" for a in alerts)


def test_exfil_ignores_normal_ratio(ctx):
    det = ExfilDetector(ctx)
    flows = [make_flow(ts=1000 + i * 5, src="10.0.1.10", dst="203.0.113.5",
                       bytes_out=1000, bytes_in=9000) for i in range(6)]
    assert _run(det, flows) == []
