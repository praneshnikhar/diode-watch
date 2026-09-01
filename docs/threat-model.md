# Threat model & detection methods

All detectors are stateful (sliding windows over flow timestamps), one-pass,
and operate strictly on passive observations.

## 1. Volumetric / protocol DDoS

**Signals**: per-destination 10s window — flow count, packet rate, distinct
source count (spoofed-source entropy proxy), SYN-only ratio, UDP ratio,
in/out byte asymmetry; per-source 10s packet rate.

**Decision**:
- ≥40 flows, ≥20 distinct sources, SYN ratio ≥0.85 → `DDOS_SYN_FLOOD`
- ≥40 flows, UDP ratio ≥0.8, byte asymmetry ≥20, ≥10 sources → `DDOS_UDP_AMPLIFICATION`
- per-source >1500 flows/s → `DDOS_VOLUMETRIC`
- IsolationForest (contamination 0.02, trained on warmup benign windows) flags
  unusual window profiles → `DDOS_ANOMALY`

**Limitations**: spoofed-source floods are indistinguishable from real source
diversity when sources rotate slowly; thresholds are tuned for the demo
traffic scale.

## 2. Botnet C2 beaconing

**Signals**: per `(src, dst, dport)` arrival history over 15 min — inter-arrival
coefficient of variation plus FFT periodogram peak/mean ratio of the occupancy
signal.

**Decision**: ≥5 arrivals and (CV < 0.3) or (CV < 0.6 and spectral peak > 8x)
or (peak > 25x) → `C2_BEACON`. Confidence blends CV regularity and spectral
significance.

**Limitations**: legitimate cron-like traffic (NTP, keepalives) can look
periodic; small packet counts and duration are used to pre-filter, but
false positives remain possible.

## 3. DGA domains & DNS tunnelling

**Signals**: query name entropy, length, 3-gram corpus anomaly (vs bundled
benign-domain corpus), digit/vowel ratio, label count, TLD reputation,
hex-lookalike flag, qtype.

**Decision**:
- LightGBM binary classifier (threshold 0.65) → `DGA_DOMAIN`
  (heuristic fallback if no model)
- entropy ≥3.6 and length ≥40, or entropy ≥4.3 and length ≥25 → `DNS_TUNNEL`
  (TXT/NULL qtype boosts confidence)

**Limitations**: DGA families in the wild drift; hence the PSI drift monitor
and retraining loop. Tunnelling that stays under entropy/length thresholds
(e.g., plain-A tunnelling) is out of scope.

## 4. Malware inside encrypted sessions

**Signals**: JA3 ClientHello fingerprint, ClientHello/ServerHello sizes,
certificate depth, handshake packet count, cipher-suite entropy.

**Decision**:
- JA3 in public threat-intel denylist → `TLS_MALWARE` at 0.9 confidence
- IsolationForest (contamination 0.05, trained on warmup benign TLS) anomaly
  strength > threshold → `TLS_MALWARE` at 0.5–0.75

**Limitations**: JA3 of unknown malware families requires the behavioural
model; enterprise middleboxes and NAT normalize fingerprints.

## 5. Reconnaissance / port scanning

**Signals**: per-source 60s window — distinct (host, port) pairs, ports per
single host, distinct hosts, SYN-only ratio.

**Decision** (requires ≥80% SYN-only probes):
- ≥64 ports on one host → vertical `RECON_SCAN`
- ≥100 distinct hosts → horizontal `RECON_SCAN`
- ≥150 distinct pairs → fan-out `RECON_SCAN`

**Limitations**: slow scans below the 60s window rate evade counting;
confidentiality of internal addressing means vertical/horizontal labels are
heuristic.

## 6. Data exfiltration

**Signals**: per `(src, dst)` 10-min window — out/in byte ratio, volume; plus a
per-source EWMA baseline of normal transfer sizes.

**Decision**:
- ratio >8 and >50 KB outbound over ≥3 flows → `DATA_EXFIL`
- single transfer >4σ above the source's learned baseline → `DATA_EXFIL`

**Limitations**: chunky legitimate uploads (backups, sync) share the ratio
signature; baseline contamination from regular large transfers reduces the
z-score signal.

## Cross-cutting properties

- **Read-only**: no code path in `engine/` initiates traffic toward observed
  IPs; the only outbound HTTP is the optional n8n webhook inside the enclave.
- **No decryption**: no crypto/TLS libraries beyond metadata parsing.
- **Streaming**: bounded per-flow work; windows pruned on access; worst-case
  per-flow latency is dominated by detector loops (<1 ms typical).
- **Standardized output**: all alerts share the v1.0 schema (see architecture
  doc) with evidence features included for auditability.
