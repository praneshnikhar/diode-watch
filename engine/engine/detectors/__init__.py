from .base import Detector
from .c2 import C2Detector
from .ddos import DdosDetector
from .dga_dns import DgaDnsDetector
from .exfil import ExfilDetector
from .recon import ReconDetector
from .tls_malware import TlsMalwareDetector

ALL_DETECTORS = [
    DdosDetector,
    C2Detector,
    DgaDnsDetector,
    TlsMalwareDetector,
    ReconDetector,
    ExfilDetector,
]

__all__ = ["Detector", "ALL_DETECTORS"]
