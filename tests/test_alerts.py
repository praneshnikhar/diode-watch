import queue

from engine.engine.alerts import AlertManager
from engine.engine.config import Config
from engine.engine.schema import Alert, severity_for


def test_severity_mapping():
    assert severity_for("DDOS_SYN_FLOOD", 0.9) == "CRITICAL"
    assert severity_for("DDOS_SYN_FLOOD", 0.5) == "HIGH"
    assert severity_for("DATA_EXFIL", 0.9) == "CRITICAL"
    assert severity_for("C2_BEACON", 0.7) == "HIGH"
    assert severity_for("DGA_DOMAIN", 0.7) == "MEDIUM"
    assert severity_for("RECON_SCAN", 0.99) == "HIGH"


def test_alert_serialization_roundtrip():
    a = Alert(threat_class="C2_BEACON", key="10.0.1.50", confidence=0.88,
              ts=1000.0, severity="HIGH", evidence={"cv": 0.05},
              explanation="beacon", src_ip="10.0.1.50", dst_ip="198.51.100.10")
    d = a.to_dict()
    assert d["schema_version"] == "1.0"
    assert d["confidence"] == 0.88
    assert "evidence" in d and "explanation" in d


def _manager():
    from unittest.mock import MagicMock
    metrics = MagicMock()
    metrics.alerts.labels.return_value.inc = MagicMock()
    cfg = Config(redis_url="x", database_url="x")
    m = AlertManager(cfg, queue.Queue(), None, metrics)
    return m


def test_cooldown_suppresses_rapid_duplicates():
    m = _manager()
    a1 = Alert(threat_class="C2_BEACON", key="h", confidence=0.9, ts=1000.0,
               severity="HIGH", evidence={}, explanation="")
    m.submit(a1)
    a2 = Alert(threat_class="C2_BEACON", key="h", confidence=0.9, ts=1010.0,
               severity="HIGH", evidence={}, explanation="")
    m.submit(a2)  # within 45s cooldown -> suppressed
    assert m.db_queue.qsize() == 1


def test_session_updates_same_alert_id():
    m = _manager()
    a1 = Alert(threat_class="DGA_DOMAIN", key="h", confidence=0.8, ts=1000.0,
               severity="MEDIUM", evidence={}, explanation="")
    m.submit(a1)
    a2 = Alert(threat_class="DGA_DOMAIN", key="h", confidence=0.9, ts=1040.0,
               severity="MEDIUM", evidence={}, explanation="")
    m.submit(a2)  # after 20s cooldown, same session (gap < 300s)
    first = m.db_queue.get()
    second = m.db_queue.get()
    assert second["alert_id"] == first["alert_id"]
    assert second["occurrences"] == 2
