"""Candidate attack-strategy generation per vulnerability class.

The exploration agent needs candidate strategies to score. This maps a finding's
vulnerability class to concrete candidate strategies with prerequisites (facts
they need in the live state) and yields (facts a success grants) — so the
adaptive scorer can gate, unlock dependents, and reinforce what lands.
"""

from __future__ import annotations

from dataclasses import dataclass

from raze.adaptive import Strategy


@dataclass(frozen=True)
class StrategyTemplate:
    suffix: str
    description: str
    prerequisites: tuple[str, ...] = ()
    yields: tuple[str, ...] = ()
    advances_chain: bool = False


# class id -> candidate strategy templates
TEMPLATES: dict[str, list[StrategyTemplate]] = {
    "sqli": [
        StrategyTemplate("union", "UNION-based data extraction", (), ("db_read",)),
        StrategyTemplate("error", "error-based extraction", (), ("db_read",)),
        StrategyTemplate("blind", "boolean/time blind extraction", (), ("db_read",)),
        StrategyTemplate("rce", "stacked query / into outfile to RCE", ("db_read",), ("shell",), True),
    ],
    "nosql_injection": [
        StrategyTemplate("authbypass", "operator injection auth bypass", (), ("auth_bypass",), True),
    ],
    "xss_reflected": [
        StrategyTemplate("session", "session/token theft via payload", (), ("session",), True),
    ],
    "xss_stored": [
        StrategyTemplate("session", "persistent session theft", (), ("session",), True),
        StrategyTemplate("ato", "admin action via victim session", ("session",), ("admin",), True),
    ],
    "ssrf": [
        StrategyTemplate("internal", "reach internal service", (), ("internal_access",), True),
    ],
    "cloud_metadata_ssrf": [
        StrategyTemplate("creds", "fetch IMDS role credentials", (), ("cloud_creds",), True),
    ],
    "file_upload": [
        StrategyTemplate("webshell", "upload and reach a web shell", (), ("shell",), True),
    ],
    "ssti": [StrategyTemplate("rce", "template payload to RCE", (), ("shell",), True)],
    "lfi_rfi": [StrategyTemplate("logpoison", "log poisoning to RCE", (), ("shell",), True)],
    "insecure_deserialization": [
        StrategyTemplate("gadget", "gadget-chain to RCE", (), ("shell",), True),
    ],
    "rce": [StrategyTemplate("exec", "execute payload", (), ("shell",), True)],
    "unauth_service": [
        StrategyTemplate("access", "unauthenticated access", (), ("service_access",)),
        StrategyTemplate("rce", "abuse service to code exec", ("service_access",), ("shell",), True),
    ],
    "default_credentials": [
        StrategyTemplate("login", "log in with default creds", (), ("service_access",)),
    ],
    "jwt_flaw": [StrategyTemplate("forge", "forge alg=none token", (), ("auth_bypass",), True)],
    "hardcoded_secret": [
        StrategyTemplate("auth", "authenticate with leaked secret", (), ("auth_bypass",), True),
    ],
    "public_bucket": [StrategyTemplate("enum", "enumerate and pull objects", (), ("bucket_data",))],
    "idor": [StrategyTemplate("enum", "enumerate object ids", (), ("other_user_data",), True)],
    "broken_auth": [StrategyTemplate("bypass", "authentication bypass", (), ("auth_bypass",), True)],
    # AD
    "kerberoasting": [
        StrategyTemplate("roast", "request TGS for SPN", (), ("tgs_hash",)),
        StrategyTemplate("crack", "offline crack of TGS", ("tgs_hash",), ("svc_creds",), True),
    ],
    "asrep_roasting": [
        StrategyTemplate("roast", "AS-REP roast (no preauth)", (), ("asrep_hash",)),
        StrategyTemplate("crack", "offline crack", ("asrep_hash",), ("user_creds",), True),
    ],
    "unconstrained_delegation": [
        StrategyTemplate("coerce", "coerce auth + capture TGT", ("shell",), ("dc_tgt",), True),
    ],
    "dcsync": [
        StrategyTemplate("replicate", "DCSync of secrets", ("domain_admin",), ("krbtgt",), True),
    ],
    "email_spoofable": [
        StrategyTemplate("phish", "send spoofed phishing (authorized)", (), ("creds",), True),
    ],
}


def _generic(class_id: str | None) -> list[StrategyTemplate]:
    label = class_id or "unknown"
    return [StrategyTemplate("attempt", f"attempt exploitation of {label}", (), ())]


def generate(finding_title: str, vuln_class: str | None, uid: str = "") -> list[Strategy]:
    templates = TEMPLATES.get(vuln_class) if vuln_class else None
    if not templates:
        templates = _generic(vuln_class)
    prefix = f"{uid}:" if uid else ""
    out: list[Strategy] = []
    for t in templates:
        out.append(
            Strategy(
                id=f"{prefix}{finding_title}:{t.suffix}",
                finding_title=finding_title,
                description=t.description,
                vuln_class=vuln_class,
                prerequisites=list(t.prerequisites),
                yields=list(t.yields),
                advances_chain=t.advances_chain,
            )
        )
    return out
