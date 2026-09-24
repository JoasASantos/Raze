"""Cryptography analyzers — weak-algorithm and low-entropy secret detection."""

from __future__ import annotations

import math
from collections import Counter

from offsec_one.topics.base import Signal

WEAK_ALGORITHMS = {
    "md5": ("high", "MD5 is broken for collision resistance"),
    "md4": ("high", "MD4 is broken"),
    "sha1": ("medium", "SHA-1 is collision-weak"),
    "des": ("high", "DES has a 56-bit key"),
    "3des": ("medium", "3DES is deprecated (Sweet32)"),
    "rc4": ("high", "RC4 is broken"),
    "ecb": ("high", "ECB mode leaks plaintext structure"),
}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class WeakAlgorithmAnalyzer:
    """Flag weak/broken cryptographic algorithms and JWT `alg: none`.

    state: {"algorithms": [str]} and/or {"jwt_alg": str}
    """

    topic = "crypto"

    def analyze(self, state: dict) -> list[Signal]:
        out: list[Signal] = []
        for algo in state.get("algorithms", []) or []:
            key = str(algo).lower().replace("-", "").replace("_", "")
            for weak, (sev, why) in WEAK_ALGORITHMS.items():
                if weak in key:
                    out.append(Signal("weak-algorithm", f"{algo}: {why}", severity=sev))
                    break
        jwt_alg = state.get("jwt_alg")
        if jwt_alg and str(jwt_alg).lower() == "none":
            out.append(
                Signal("jwt-alg-none", "JWT accepts alg=none — signature bypass", severity="critical")
            )
        return out


class SecretEntropyAnalyzer:
    """Flag a low-entropy secret/key (guessable).

    state: {"secret": str}  (min_bits threshold optional via {"min_entropy_bits": float})
    """

    topic = "crypto"

    def analyze(self, state: dict) -> list[Signal]:
        secret = state.get("secret")
        if not secret:
            return []
        threshold = float(state.get("min_entropy_bits", 3.0))
        bits = shannon_entropy(secret)
        if bits < threshold:
            return [
                Signal(
                    "low-entropy-secret",
                    f"secret entropy {bits:.2f} bits/char below {threshold} — guessable",
                    severity="high",
                )
            ]
        return []
