"""Map a finding's signals to a vulnerability class (deterministic).

Turns analyzer signal names into a `VulnClass`, so decisions can be adapted per
class: severity seeded from the class's typical CVSS, CWE attached, chain rules
keyed by class. Strongest signal (by severity) wins; falls back to the topic's
first class.
"""

from __future__ import annotations

from raze.topics.base import Signal
from raze.vulnclasses import CLASSES, VulnClass, by_topic

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SIGNAL_CLASS: dict[str, str] = {
    # web
    "sql-error": "sqli",
    "unescaped-reflection": "xss_reflected",
    "reflection": "xss_reflected",
    "open-redirect": "open_redirect",
    "cors-misconfig": "cors_misconfig",
    "clickjacking": "clickjacking",
    "insecure-cookie": "weak_session",
    "missing-header": "security_misconfig",
    # network
    "risky-port": "unauth_service",
    # cloud
    "metadata-endpoint": "cloud_metadata_ssrf",
    "public-bucket": "public_bucket",
    # crypto
    "jwt-alg-none": "jwt_flaw",
    "weak-algorithm": "weak_crypto",
    "low-entropy-secret": "hardcoded_secret",
    # ad
    "kerberoastable": "kerberoasting",
    "asrep-roastable": "asrep_roasting",
    "unconstrained-delegation": "unconstrained_delegation",
    # mobile
    "cleartext-traffic": "mobile_insecure_storage",
    "backup-allowed": "mobile_insecure_storage",
    "debuggable": "mobile_insecure_storage",
    "exported-component": "mobile_exported_component",
    # wireless
    "wifi-encryption": "wifi_weak_enc",
    "wps-enabled": "wifi_weak_enc",
    "weak-cipher": "wifi_weak_enc",
    # exploitdev
    "no-nx": "missing_mitigations",
    "no-canary": "missing_mitigations",
    "no-pie": "missing_mitigations",
    "no-aslr": "missing_mitigations",
    "weak-relro": "missing_mitigations",
    # reversing
    "dangerous-import": "memory_corruption",
    "interesting-string": "embedded_secret",
    # social
    "no-spf": "email_spoofable",
    "no-dkim": "email_spoofable",
    "no-dmarc": "email_spoofable",
    "dmarc-monitor-only": "email_spoofable",
    "lookalike-domain": "email_spoofable",
}


def infer_class(topic: str, signals: list[Signal]) -> VulnClass | None:
    for s in sorted(signals, key=lambda x: _SEV_ORDER.get(x.severity, 0), reverse=True):
        cid = SIGNAL_CLASS.get(s.name)
        if cid and cid in CLASSES:
            return CLASSES[cid]
    candidates = by_topic(topic)
    return candidates[0] if candidates else None
