from simulator.simulator.flowlib import make_flow
from simulator.simulator.scenarios import Orchestrator, tunnel_qname
from simulator.simulator.emit import _CLASS_OF


def _drive(orch, sim_span, step=5.0, sample=None, max_samples=200):
    """Run the orchestrator, counting flows instead of storing them all."""
    counts = {"flows": 0, "truth": 0}
    labels = set()

    def emit(flow, label):
        counts["flows"] += 1
        if sample is not None and counts["flows"] <= max_samples:
            sample.append(flow)
        if label:
            counts["truth"] += 1
            labels.add(label)

    t = 0.0
    while t < sim_span:
        orch.tick(t, step, emit)
        t += step
    return counts, labels


def test_all_attack_labels_emitted():
    orch = Orchestrator(seed=42, flows_per_sec=200)
    counts, labels = _drive(orch, 20000)
    expected = {"ddos_syn_flood", "ddos_udp_amplification", "c2_beacon", "dga",
                "dns_tunnel", "tls_malware", "port_scan", "exfil"}
    assert expected.issubset(labels), f"missing {expected - labels}"
    assert counts["flows"] > 100_000
    assert counts["truth"] > 1000


def test_flows_never_carry_labels():
    """The detection engine must never see ground truth: labels live on a
    separate side channel (the emitter's truth stream), not in flow records."""
    orch = Orchestrator(seed=1, flows_per_sec=100)
    sample = []
    counts, _ = _drive(orch, 5000, sample=sample)
    assert sample, "no flows emitted"
    for f in sample:
        assert "label" not in f
        assert "class" not in f


def test_flow_record_fields():
    f = make_flow(100.0, "10.0.0.1", "203.0.113.1", 40000, 443, "tcp",
                  10, 1000, 9000, 1.5, flags=["PSH", "ACK"],
                  dns=None, tls={"ja3": "abc"})
    for k in ("ts", "flow_id", "src_ip", "dst_ip", "src_port", "dst_port",
              "proto", "packets", "bytes_out", "bytes_in", "duration"):
        assert k in f


def test_truth_class_mapping():
    for label, cls in _CLASS_OF.items():
        assert cls.startswith(("DDOS", "C2", "DGA", "DNS", "TLS", "RECON", "DATA"))


def test_tunnel_qname_entropy():
    from engine.engine.features import shannon_entropy
    import random
    rng = random.Random(3)
    q = tunnel_qname(rng)
    assert len(q) > 40
    assert shannon_entropy(q.split(".")[0]) > 3.5
