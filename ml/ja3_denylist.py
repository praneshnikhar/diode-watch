"""JA3 fingerprint denylist from public threat-intel reports.

References (public analyses of TLS-fingerprinted malware families):
- TrickBot / Emotet / Qakbot / Dridex C2 fingerprints
- Cobalt Strike default TLS profile
- Meterpreter HTTPS listener profile

JA3 hashes are computed over the ClientHello cipher/extension order, so they
are usable from passively captured TLS metadata without decryption.
"""

KNOWN_BAD_JA3 = {
    "6734f37431670b3ab4292b8f60f29984": "TrickBot C2",
    "44d04c1d4791ab1e30b106b7f00eae41": "Emotet epoch-1",
    "b386946a5a44d1ddcc843bc75336dfce": "Qakbot C2",
    "51c64c77e60f3980eea90869b68c58a8": "Dridex C2",
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike default profile",
    "3e7cc7cb33bb2ddecf4f6b05a75ed2a8": "Meterpreter HTTPS",
}
