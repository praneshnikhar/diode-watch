"""Flow record + alert schemas (standardized, versioned)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

ALERT_SCHEMA_VERSION = "1.0"

THREAT_CLASSES = (
    "DDOS_SYN_FLOOD",
    "DDOS_UDP_AMPLIFICATION",
    "DDOS_VOLUMETRIC",
    "DDOS_ANOMALY",
    "C2_BEACON",
    "DGA_DOMAIN",
    "DNS_TUNNEL",
    "TLS_MALWARE",
    "RECON_SCAN",
    "DATA_EXFIL",
)

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass
class Flow:
    ts: float
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    packets: int
    bytes_out: int
    bytes_in: int
    duration: float
    flags: list[str] = field(default_factory=list)
    dns: dict[str, Any] | None = None
    tls: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Flow":
        return cls(
            ts=float(d.get("ts", 0)),
            flow_id=str(d.get("flow_id", uuid.uuid4().hex)),
            src_ip=str(d.get("src_ip", "0.0.0.0")),
            dst_ip=str(d.get("dst_ip", "0.0.0.0")),
            src_port=int(d.get("src_port", 0)),
            dst_port=int(d.get("dst_port", 0)),
            proto=str(d.get("proto", "tcp")),
            packets=int(d.get("packets", 0)),
            bytes_out=int(d.get("bytes_out", 0)),
            bytes_in=int(d.get("bytes_in", 0)),
            duration=float(d.get("duration", 0.0)),
            flags=[str(f) for f in d.get("flags", [])] if d.get("flags") else [],
            dns=d.get("dns") or None,
            tls=d.get("tls") or None,
        )

    @property
    def is_syn_only(self) -> bool:
        return self.proto == "tcp" and self.flags == ["SYN"]


@dataclass
class Alert:
    threat_class: str
    key: str
    confidence: float
    ts: float
    severity: str
    evidence: dict[str, Any]
    explanation: str
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    flow_id: str | None = None
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    proto: str = ""
    occurrences: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ALERT_SCHEMA_VERSION,
            "alert_id": self.alert_id,
            "ts": self.ts,
            "threat_class": self.threat_class,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "key": self.key,
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "occurrences": self.occurrences,
        }


def severity_for(threat_class: str, confidence: float) -> str:
    if threat_class.startswith("DDOS_"):
        return "CRITICAL" if confidence >= 0.8 else "HIGH"
    if threat_class in ("DATA_EXFIL",):
        return "CRITICAL" if confidence >= 0.8 else "HIGH"
    if threat_class in ("C2_BEACON", "DNS_TUNNEL", "TLS_MALWARE"):
        return "HIGH"
    if threat_class == "DGA_DOMAIN":
        return "HIGH" if confidence >= 0.9 else "MEDIUM"
    if threat_class == "RECON_SCAN":
        return "HIGH" if confidence >= 0.9 else "MEDIUM"
    return "LOW"
