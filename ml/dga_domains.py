"""DGA domain-family generators.

Reproduces the *style* of known DGA families (random letters, hex labels,
word+digit combos) so the simulator can emit realistic-looking malicious
domains. These are synthetic lookalikes, not real malware domains.
"""

from __future__ import annotations

import random
import string

DGA_TLDS = [".xyz", ".top", ".club", ".info", ".work", ".click", ".link", ".buzz", ".pw", ".tk"]
HEX_TLDS = [".com", ".net", ".info", ".org"]

DGA_WORDS = [
    "blue", "gold", "fast", "cloud", "alpha", "delta", "storm", "night", "red", "silver",
    "mega", "turbo", "ultra", "cyber", "data", "net", "web", "xen", "quant", "shadow",
]


def family_random_letters(rng: random.Random) -> str:
    n = rng.randint(10, 16)
    label = "".join(rng.choice(string.ascii_lowercase) for _ in range(n))
    return label + rng.choice(DGA_TLDS)


def family_hex(rng: random.Random) -> str:
    n = rng.randint(16, 20)
    label = "".join(rng.choice("0123456789abcdef") for _ in range(n))
    return label + rng.choice(HEX_TLDS)


def family_word_digits(rng: random.Random) -> str:
    w1 = rng.choice(DGA_WORDS)
    w2 = rng.choice(DGA_WORDS)
    digits = "".join(rng.choice(string.digits) for _ in range(rng.randint(2, 4)))
    sep = rng.choice(["", "-"])
    return f"{w1}{sep}{w2}{digits}{rng.choice(HEX_TLDS)}"


def family_reversewords(rng: random.Random) -> str:
    words = [rng.choice(DGA_WORDS) for _ in range(2)]
    label = "".join(w[::-1] for w in words)
    return label + rng.choice(DGA_TLDS)


FAMILIES = [family_random_letters, family_hex, family_word_digits, family_reversewords]


def generate_dga_domain(rng: random.Random) -> str:
    return rng.choice(FAMILIES)(rng)


def generate_dga_domains(n: int, seed: int | None = None) -> list[str]:
    rng = random.Random(seed)
    return [generate_dga_domain(rng) for _ in range(n)]
