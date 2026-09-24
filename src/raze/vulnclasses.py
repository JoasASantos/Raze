"""Vulnerability-class taxonomy for Raze.

A registry of offensive-security vulnerability classes, each bound to its CWE(s),
its Raze topic, an OWASP category where applicable, and a *typical* CVSS v3.1
base vector. The typical vector yields a default severity (via raze.cvss) that
seeds impact/priority when a finding has no measured vector yet.

The typical vector is a heuristic starting point, NOT the score for a specific
finding — always prefer a measured vector for a real report.
"""

from __future__ import annotations

from dataclasses import dataclass

from raze.cvss import base_score, cvss_to_severity
from raze.judgments import Severity


@dataclass(frozen=True)
class VulnClass:
    id: str
    name: str
    topic: str
    cwe: tuple[str, ...]
    typical_cvss: str
    owasp: str = ""
    notes: str = ""

    @property
    def typical_score(self) -> float:
        return base_score(self.typical_cvss)

    @property
    def typical_severity(self) -> Severity:
        return cvss_to_severity(self.typical_cvss)


def _c(id, name, topic, cwe, cvss, owasp="", notes=""):
    return VulnClass(id, name, topic, tuple(cwe), cvss, owasp, notes)


_HIGH_NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_XSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
_MED_NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"

CLASSES: dict[str, VulnClass] = {c.id: c for c in [
    # ---- web / API ----
    _c("xss_reflected", "Reflected XSS", "web", ["CWE-79"], _XSS, "A03:2021 Injection"),
    _c("xss_stored", "Stored XSS", "web", ["CWE-79"],
       "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N", "A03:2021 Injection"),
    _c("sqli", "SQL Injection", "web", ["CWE-89"], _HIGH_NET, "A03:2021 Injection"),
    _c("command_injection", "OS Command Injection", "web", ["CWE-78"], _HIGH_NET, "A03:2021 Injection"),
    _c("ssti", "Server-Side Template Injection", "web", ["CWE-1336", "CWE-94"], _HIGH_NET,
       "A03:2021 Injection"),
    _c("ssrf", "Server-Side Request Forgery", "web", ["CWE-918"],
       "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N", "A10:2021 SSRF"),
    _c("open_redirect", "Open Redirect", "web", ["CWE-601"],
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    _c("path_traversal", "Path Traversal", "web", ["CWE-22"],
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A01:2021 Broken Access Control"),
    _c("xxe", "XML External Entity", "web", ["CWE-611"],
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A05:2021 Security Misconfiguration"),
    _c("insecure_deserialization", "Insecure Deserialization", "web", ["CWE-502"], _HIGH_NET,
       "A08:2021 Software and Data Integrity Failures"),
    _c("idor", "IDOR / BOLA", "web", ["CWE-639"],
       "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "A01:2021 Broken Access Control"),
    _c("broken_auth", "Broken Authentication", "web", ["CWE-287"], _HIGH_NET,
       "A07:2021 Identification and Authentication Failures"),
    _c("broken_access_control", "Broken Access Control", "web", ["CWE-284"],
       "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "A01:2021 Broken Access Control"),
    _c("mass_assignment", "Mass Assignment / BOPLA", "web", ["CWE-915"],
       "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "A08:2021"),
    _c("csrf", "Cross-Site Request Forgery", "web", ["CWE-352"],
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"),
    _c("file_upload", "Unrestricted File Upload", "web", ["CWE-434"], _HIGH_NET, "A04:2021"),
    _c("lfi_rfi", "File Inclusion (LFI/RFI)", "web", ["CWE-98"], _HIGH_NET, "A03:2021 Injection"),
    _c("security_misconfig", "Security Misconfiguration", "web", ["CWE-16", "CWE-693"], _MED_NET,
       "A05:2021 Security Misconfiguration"),
    _c("sensitive_data_exposure", "Sensitive Data Exposure", "web", ["CWE-200"],
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A02:2021 Cryptographic Failures"),
    _c("rce", "Remote Code Execution", "web", ["CWE-94"], _HIGH_NET, "A03:2021 Injection"),
    # ---- network ----
    _c("unauth_service", "Unauthenticated Service Exposure", "network", ["CWE-306"], _HIGH_NET),
    _c("cleartext_protocol", "Cleartext Protocol", "network", ["CWE-319"],
       "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    # ---- crypto ----
    _c("jwt_flaw", "JWT Signature Flaw", "crypto", ["CWE-347"], _HIGH_NET),
    _c("weak_crypto", "Weak Cryptographic Algorithm", "crypto", ["CWE-327"], _MED_NET),
    _c("hardcoded_secret", "Hardcoded / Weak Secret", "crypto", ["CWE-798", "CWE-321", "CWE-331"],
       _HIGH_NET),
    # ---- active directory ----
    _c("kerberoasting", "Kerberoasting", "ad", ["CWE-522"],
       "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    _c("asrep_roasting", "AS-REP Roasting", "ad", ["CWE-522"],
       "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    _c("unconstrained_delegation", "Unconstrained Delegation", "ad", ["CWE-266"], _HIGH_NET),
    _c("dcsync", "DCSync", "ad", ["CWE-269"], _HIGH_NET),
    # ---- cloud ----
    _c("public_bucket", "Public Object Storage", "cloud", ["CWE-732"],
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    _c("cloud_metadata_ssrf", "Cloud Metadata SSRF", "cloud", ["CWE-918"], _HIGH_NET),
    _c("iam_misconfig", "IAM Misconfiguration", "cloud", ["CWE-266"], _HIGH_NET),
    _c("subdomain_takeover", "Subdomain Takeover", "cloud", ["CWE-350"],
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"),
    # ---- mobile ----
    _c("mobile_insecure_storage", "Insecure Data Storage", "mobile", ["CWE-312"],
       "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    _c("mobile_exported_component", "Exported Component", "mobile", ["CWE-926"],
       "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    # ---- wireless ----
    _c("wifi_weak_enc", "Weak Wi-Fi Encryption", "wireless", ["CWE-327"],
       "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    # ---- exploit dev / reversing ----
    _c("memory_corruption", "Memory Corruption", "exploitdev", ["CWE-787", "CWE-416"], _HIGH_NET),
    _c("missing_mitigations", "Missing Exploit Mitigations", "exploitdev", ["CWE-693"], _MED_NET),
    _c("embedded_secret", "Embedded Secret in Binary", "reversing", ["CWE-798"], _HIGH_NET),
    # ---- social ----
    _c("email_spoofable", "Spoofable Email Domain", "social", ["CWE-290"],
       "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"),
]}


def by_cwe(cwe: str) -> list[VulnClass]:
    return [c for c in CLASSES.values() if cwe in c.cwe]


def by_topic(topic: str) -> list[VulnClass]:
    return [c for c in CLASSES.values() if c.topic == topic]


def get(class_id: str) -> VulnClass | None:
    return CLASSES.get(class_id)
