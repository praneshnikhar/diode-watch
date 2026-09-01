"""Feature extraction utilities shared by detectors and models."""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".info", ".work", ".click", ".link",
                   ".buzz", ".pw", ".tk", ".bid", ".win", ".download"}

_RE_DIGIT = re.compile(r"\d")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return len(_RE_DIGIT.findall(s)) / len(s)


def vowel_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if c in "aeiou") / len(s)


def _load_ngram_corpus() -> tuple[set[str], float]:
    for base in (Path(__file__).resolve().parents[2], Path.cwd(), Path("/app")):
        p = base / "ml" / "data" / "legit_domains.txt"
        if p.exists():
            domains = [ln.strip().split(".")[0] for ln in p.read_text().splitlines()
                       if ln.strip()]
            ngrams: Counter[str] = Counter()
            total = 0
            for d in domains:
                ds = d.lower()
                for i in range(len(ds) - 2):
                    ngrams[ds[i:i + 3]] += 1
                    total += 1
            # Keep every trigram observed in the benign corpus. The corpus *is*
            # the definition of benign, so even single-occurrence trigrams are
            # legitimate; filtering by frequency would wrongly inflate anomaly
            # scores for rare-but-valid names (e.g. "google").
            keep = {ng for ng, c in ngrams.items() if c >= 1}
            return keep, float(total)
    return set(), 0.0


_NGRAM_CORPUS, _NGRAM_TOTAL = _load_ngram_corpus()


def ngram_anomaly(domain: str) -> float:
    """Fraction of 3-grams in `domain` that never appear in benign names."""
    if not _NGRAM_CORPUS:
        return 0.0
    ds = domain.lower()
    ngrams = [ds[i:i + 3] for i in range(len(ds) - 2)]
    if not ngrams:
        return 0.0
    return sum(1 for ng in ngrams if ng not in _NGRAM_CORPUS) / len(ngrams)


def tld_of(domain: str) -> str:
    return "." + domain.rsplit(".", 1)[-1] if "." in domain else ""


DGA_FEATURE_NAMES = [
    "entropy", "length", "ngram_anomaly", "digit_ratio", "vowel_ratio",
    "label_count", "tld_suspicious", "is_hex",
]


def dga_features(domain: str) -> dict[str, float]:
    ds = domain.rstrip(".").lower()
    labels = ds.split(".")
    base = labels[0]
    return {
        "entropy": shannon_entropy(base),
        "length": float(len(base)),
        "ngram_anomaly": ngram_anomaly(base),
        "digit_ratio": digit_ratio(base),
        "vowel_ratio": vowel_ratio(base),
        "label_count": float(len(labels)),
        "tld_suspicious": 1.0 if tld_of(ds) in SUSPICIOUS_TLDS else 0.0,
        "is_hex": 1.0 if (len(base) >= 12 and re.fullmatch(r"[0-9a-f]+", base)) else 0.0,
    }


def dga_feature_vector(domain: str) -> list[float]:
    f = dga_features(domain)
    return [f[n] for n in DGA_FEATURE_NAMES]


TLS_FEATURE_NAMES = [
    "client_hello_size", "server_hello_size", "cert_depth", "handshake_packets",
    "cipher_entropy", "packet_size_ratio",
]


def tls_feature_vector(tls: dict) -> list[float]:
    return [
        float(tls.get("client_hello_size", 0)),
        float(tls.get("server_hello_size", 0)),
        float(tls.get("cert_depth", 0)),
        float(tls.get("handshake_packets", 0)),
        float(tls.get("cipher_entropy", 0.0)),
        float(tls.get("handshake_packets", 0)) / max(1.0, float(tls.get("packets", 1))),
    ]


DDOS_FEATURE_NAMES = [
    "flow_count", "packet_rate", "distinct_src", "syn_ratio", "udp_ratio",
    "bytes_asymmetry",
]


def ddos_feature_vector(n_flows: int, packets: int, distinct_src: int,
                        syn_ratio: float, udp_ratio: float, bytes_asym: float) -> list[float]:
    return [
        float(n_flows), float(packets), float(distinct_src),
        syn_ratio, udp_ratio, bytes_asym,
    ]
