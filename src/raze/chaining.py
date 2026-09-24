"""Attack chaining — rule-based multi-step paths across vulnerability classes.

Beyond "several findings on one target" (see engagement._correlate), real
offensive value comes from *chains*: one weakness enables the next. These
deterministic rules fire when an engagement contains the enabling classes of a
known path, boost the members' priority, and describe the path.
"""

from __future__ import annotations

from dataclasses import dataclass

from raze.decide import Decision


@dataclass
class AttackChain:
    label: str  # target host, or a chain-rule name for cross-class paths
    steps: list[str]
    chain_priority: float
    why: str
    kind: str = "target"  # "target" | "class-path"

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "kind": self.kind,
            "steps": self.steps,
            "chain_priority": round(self.chain_priority, 2),
            "why": self.why,
        }


@dataclass(frozen=True)
class ChainRule:
    name: str
    stages: tuple[str, ...]  # vuln-class ids, in path order
    goal: str
    bonus: float = 10.0
    min_stages: int = 2  # how many stages must be present to fire


CHAIN_RULES: tuple[ChainRule, ...] = (
    ChainRule("ssrf-to-cloud-takeover", ("ssrf", "cloud_metadata_ssrf", "iam_misconfig"),
              "SSRF -> cloud metadata -> IAM -> account takeover", 15.0),
    ChainRule("exposed-service-to-rce", ("unauth_service", "rce"),
              "exposed service -> code execution on host", 12.0),
    ChainRule("ad-domain-compromise",
              ("kerberoasting", "asrep_roasting", "unconstrained_delegation", "dcsync"),
              "credential roast -> delegation abuse -> domain compromise", 15.0),
    ChainRule("secret-to-auth-bypass", ("hardcoded_secret", "jwt_flaw", "broken_auth"),
              "leaked/forgeable secret -> token forgery -> auth bypass", 12.0),
    ChainRule("xss-to-account-takeover", ("xss_stored", "broken_auth"),
              "stored XSS -> session theft -> account takeover", 10.0),
    ChainRule("traversal-to-secret", ("path_traversal", "sensitive_data_exposure", "hardcoded_secret"),
              "path traversal -> read secrets -> escalate", 10.0),
    ChainRule("recon-to-exploit", ("security_misconfig", "sqli", "rce"),
              "misconfig surface -> injection -> RCE", 8.0),
    ChainRule("idor-to-data-breach", ("idor", "sensitive_data_exposure"),
              "IDOR/BOLA -> mass data exfiltration", 10.0),
    ChainRule("upload-to-rce", ("file_upload", "rce"),
              "unrestricted upload -> web shell -> RCE", 14.0),
    ChainRule("deserialize-to-rce", ("insecure_deserialization", "rce"),
              "insecure deserialization -> RCE", 14.0),
    ChainRule("ssti-to-rce", ("ssti", "rce"),
              "template injection -> RCE", 13.0),
    ChainRule("lfi-to-rce", ("lfi_rfi", "rce"),
              "file inclusion -> log poisoning -> RCE", 12.0),
    ChainRule("open-redirect-to-oauth-theft", ("open_redirect", "broken_auth"),
              "open redirect -> OAuth token/code theft -> account takeover", 10.0),
    ChainRule("subdomain-takeover-to-phishing", ("subdomain_takeover", "email_spoofable"),
              "subdomain takeover + spoofable domain -> credible phishing", 9.0),
    ChainRule("cleartext-to-cred-theft", ("cleartext_protocol", "broken_auth", "default_credentials"),
              "cleartext protocol -> credential capture -> auth bypass", 11.0),
    ChainRule("cors-to-data-theft", ("cors_misconfig", "sensitive_data_exposure"),
              "CORS misconfig -> cross-origin data theft", 10.0),
    ChainRule("mobile-storage-to-secret", ("mobile_insecure_storage", "hardcoded_secret"),
              "insecure storage -> extracted secret -> backend access", 10.0),
    ChainRule("wifi-to-network-foothold", ("wifi_weak_enc", "unauth_service"),
              "Wi-Fi break -> internal network -> exposed service", 11.0),
    ChainRule("nosql-to-auth-bypass", ("nosql_injection", "broken_auth"),
              "NoSQL injection -> authentication bypass", 12.0),
    ChainRule("padding-oracle-to-forgery", ("padding_oracle", "broken_auth"),
              "padding oracle -> token decrypt/forge -> auth bypass", 11.0),
    ChainRule("session-to-takeover", ("weak_session", "broken_auth"),
              "weak session handling -> fixation/hijack -> account takeover", 9.0),
)


def detect_class_chains(decisions: list[Decision]) -> list[AttackChain]:
    """Fire chain rules over the engagement's decided classes; boost members."""
    by_class: dict[str, list[Decision]] = {}
    for d in decisions:
        if d.vuln_class:
            by_class.setdefault(d.vuln_class, []).append(d)

    chains: list[AttackChain] = []
    for rule in CHAIN_RULES:
        present = [s for s in rule.stages if s in by_class]
        if len(present) < rule.min_stages:
            continue
        members: list[Decision] = []
        for stage in present:
            members.extend(by_class[stage])
        for d in members:
            d.priority = min(100.0, d.priority + rule.bonus)
        steps = [max(by_class[s], key=lambda d: d.priority).finding_title for s in present]
        chains.append(
            AttackChain(
                label=rule.name,
                steps=steps,
                chain_priority=max(d.priority for d in members),
                why=f"{rule.goal} ({len(present)}/{len(rule.stages)} stages present)",
                kind="class-path",
            )
        )
    return sorted(chains, key=lambda c: c.chain_priority, reverse=True)
