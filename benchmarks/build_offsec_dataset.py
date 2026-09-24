"""Build the robust OffSec labeled benchmark dataset.

Curated, high-signal cases across every topic. Each case carries metadata (CWE,
label rationale, difficulty) OUTSIDE the `finding` object so the runner/exporter
(which read only `finding` + `exploitable_truth`) ignore it, while humans and
future tooling can use it.

Design rules for a serious benchmark:
- Mix clear positives, clear negatives, and HARD cases where a real analyzer
  signal is present but the finding is NOT exploitable (weak-but-not-broken,
  missing-hardening-without-a-vuln, needs-preconditions). A model that fires on
  any signal must lose points here.
- Include cases with NO analyzer signal at all, to test judgment beyond the
  deterministic detectors.
- Keep states in the exact shape the analyzers consume.

Regenerate:  python benchmarks/build_offsec_dataset.py
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from raze.classify import infer_class
from raze.topics import analyze

# (topic, title, state, exploitable_truth, cwe, difficulty, rationale)
CASES: list[tuple] = [
    # ---------------- web ----------------
    ("web", "Reflected XSS, unescaped, no CSP",
     {"param_value": "<svg onload=alert(1)>", "response_body": "results for <svg onload=alert(1)>",
      "response_headers": {"Server": "nginx"}}, True, "CWE-79", "easy",
     "Dangerous chars reflected unencoded, no CSP to mitigate."),
    ("web", "Reflection but HTML-encoded",
     {"param_value": "<b>x</b>", "response_body": "q=&lt;b&gt;x&lt;/b&gt;",
      "response_headers": {"Content-Security-Policy": "default-src 'self'"}}, False, "CWE-79", "medium",
     "Input encoded on output; CSP present. Not exploitable."),
    ("web", "Stored XSS in comment field",
     {"param_value": "<img src=x onerror=fetch('//c2')>",
      "response_body": "<div class=comment><img src=x onerror=fetch('//c2')></div>"}, True, "CWE-79", "easy",
     "Payload persisted and rendered unescaped."),
    ("web", "Error-based SQLi (MySQL)",
     {"response_body": "You have an error in your SQL syntax near ''1'"}, True, "CWE-89", "easy",
     "DB error leaks into response on quote injection."),
    ("web", "SQL-like word in normal content (no error)",
     {"response_body": "Our SQL training course covers syntax basics."}, False, "CWE-89", "hard",
     "Contains 'SQL' and 'syntax' but is benign prose, no DB error signature."),
    ("web", "Open redirect via next= param",
     {"location_header": "https://evil.example/phish", "param_value": "https://evil.example/phish"}, True,
     "CWE-601", "easy", "Location driven by user input to external host."),
    ("web", "Redirect to internal path only",
     {"location_header": "/dashboard", "param_value": "/dashboard"}, False, "CWE-601", "medium",
     "Relative internal redirect, not attacker-controlled external."),
    ("web", "Missing security headers only",
     {"response_headers": {"Server": "nginx"}}, False, "CWE-693", "medium",
     "Missing CSP/HSTS is hardening debt, not an exploitable finding by itself."),
    ("web", "SSRF via url param to internal service",
     {"param_value": "http://127.0.0.1:8080/admin",
      "response_body": "internal admin panel: users=..."}, True, "CWE-918", "medium",
     "Server fetched attacker-supplied internal URL and returned its content."),
    # ---------------- network ----------------
    ("network", "Unauthenticated Redis exposed", {"open_ports": [6379]}, True, "CWE-306", "easy",
     "Redis with no auth on the network = RCE/data access."),
    ("network", "Unauthenticated MongoDB exposed", {"open_ports": [27017]}, True, "CWE-306", "easy",
     "MongoDB default no-auth exposure."),
    ("network", "Docker API exposed", {"open_ports": [2375]}, True, "CWE-306", "easy",
     "Unauthenticated Docker API = host RCE."),
    ("network", "Only SSH and HTTP open", {"open_ports": [22, 80]}, False, "CWE-200", "medium",
     "Standard managed services, no exposed datastore."),
    ("network", "Telnet open on legacy device", {"open_ports": [23]}, True, "CWE-319", "medium",
     "Cleartext admin protocol; credentials sniffable, often default creds."),
    ("network", "FTP open, anonymous unknown", {"open_ports": [21, 443]}, False, "CWE-319", "hard",
     "FTP present but exposure depends on anon/creds; not exploitable without more."),
    # ---------------- crypto ----------------
    ("crypto", "JWT accepts alg=none", {"jwt_alg": "none"}, True, "CWE-347", "easy",
     "Signature bypass; forge any token."),
    ("crypto", "MD5 used for content ETag", {"algorithms": ["md5"]}, False, "CWE-327", "hard",
     "Weak hash but used for non-security integrity; not exploitable."),
    ("crypto", "MD5 used to hash passwords", {"algorithms": ["md5"], "context": "password-storage"},
     True, "CWE-916", "medium", "Fast unsalted hash for passwords = crackable at scale."),
    ("crypto", "Low-entropy signing secret", {"secret": "aaaaaaaa"}, True, "CWE-331", "easy",
     "Guessable key; forge signatures."),
    ("crypto", "High-entropy secret", {"secret": "G7#kQ9v!zL2@pR5^wX8&nM4"}, False, "CWE-331", "medium",
     "Strong random secret, not guessable."),
    ("crypto", "3DES in transit", {"algorithms": ["3des"]}, False, "CWE-327", "hard",
     "Deprecated (Sweet32) but not trivially exploitable in most deployments."),
    # ---------------- ad ----------------
    ("ad", "Unconstrained delegation on server",
     {"accounts": [{"name": "SRV01$", "unconstrained_delegation": True}]}, True, "CWE-266", "medium",
     "Capture TGTs of connecting privileged users."),
    ("ad", "Kerberoastable privileged service account",
     {"accounts": [{"name": "svc_sql", "spn": True, "admin": True}]}, True, "CWE-522", "medium",
     "SPN on admin account; offline crack of TGS to DA."),
    ("ad", "Kerberoastable low-priv, strong password",
     {"accounts": [{"name": "svc_web", "spn": True, "admin": False}]}, False, "CWE-522", "hard",
     "Roastable but non-privileged and strong pwd; low practical impact."),
    ("ad", "AS-REP roastable admin",
     {"accounts": [{"name": "admin_bak", "asrep": True, "admin": True}]}, True, "CWE-522", "medium",
     "DONT_REQ_PREAUTH on privileged account."),
    ("ad", "Normal account, no flags",
     {"accounts": [{"name": "jdoe", "spn": False, "admin": False}]}, False, "CWE-noinfo", "easy",
     "No roastable/delegation flags."),
    # ---------------- cloud ----------------
    ("cloud", "Public S3 bucket (AllUsers)",
     {"bucket_acl": {"grants": ["AllUsers"]}}, True, "CWE-732", "easy",
     "World-readable object storage."),
    ("cloud", "Private bucket",
     {"bucket_acl": {"grants": ["owner"], "public": False}}, False, "CWE-732", "easy",
     "No public grant."),
    ("cloud", "SSRF to AWS metadata",
     {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}, True, "CWE-918", "easy",
     "Reaches IMDS; steal role credentials."),
    ("cloud", "Request to GCP metadata host",
     {"url": "http://metadata.google.internal/computeMetadata/v1/"}, True, "CWE-918", "medium",
     "GCP metadata endpoint reachable."),
    ("cloud", "External API call (not metadata)",
     {"url": "https://api.stripe.com/v1/charges"}, False, "CWE-918", "medium",
     "Legitimate external egress, not a metadata SSRF."),
    # ---------------- mobile ----------------
    ("mobile", "Debuggable release build", {"debuggable": True}, True, "CWE-489", "medium",
     "Attacker can attach a debugger to a release app."),
    ("mobile", "Cleartext traffic allowed", {"cleartext_traffic": True}, True, "CWE-319", "medium",
     "App sends data over HTTP; MITM."),
    ("mobile", "allowBackup only", {"allow_backup": True}, False, "CWE-530", "hard",
     "Backup extraction needs local/adb access; low remote impact alone."),
    ("mobile", "Exported activity without permission",
     {"exported_components": [{"name": ".AdminActivity", "permission": None}]}, True, "CWE-926", "medium",
     "Any app can invoke a sensitive exported component."),
    ("mobile", "Exported component with signature permission",
     {"exported_components": [{"name": ".SyncService", "permission": "signature"}]}, False, "CWE-926",
     "hard", "Guarded by signature-level permission."),
    # ---------------- wireless ----------------
    ("wireless", "Open Wi-Fi", {"encryption": "open"}, True, "CWE-319", "easy",
     "No encryption; passive capture and injection."),
    ("wireless", "WEP", {"encryption": "wep"}, True, "CWE-327", "easy",
     "WEP crackable in minutes."),
    ("wireless", "WPA2 with WPS enabled", {"encryption": "wpa2", "wps_enabled": True}, True, "CWE-307",
     "medium", "WPS PIN brute force / Pixie-Dust recovers PSK."),
    ("wireless", "WPA2 strong PSK, no WPS", {"encryption": "wpa2", "wps_enabled": False}, False,
     "CWE-noinfo", "medium", "Only offline crack of a strong PSK; not practically exploitable."),
    ("wireless", "WPA3 SAE", {"encryption": "wpa3"}, False, "CWE-noinfo", "hard",
     "SAE resists offline crack; check transition mode separately."),
    # ---------------- exploitdev ----------------
    ("exploitdev", "No NX and no canary, with known overflow",
     {"nx": False, "canary": False, "has_known_overflow": True}, True, "CWE-787", "medium",
     "Missing mitigations plus an actual overflow primitive = exploitable."),
    ("exploitdev", "Missing mitigations, no vuln", {"nx": False, "canary": False}, False, "CWE-693",
     "hard", "Weak hardening is not a vulnerability without a primitive."),
    ("exploitdev", "Full mitigations", {"nx": True, "canary": True, "pie": True, "relro": "full"},
     False, "CWE-noinfo", "easy", "Hardened binary, nothing to flag."),
    ("exploitdev", "No PIE, partial RELRO", {"pie": False, "relro": "partial"}, False, "CWE-693", "hard",
     "Lowers the bar but not exploitable alone."),
    # ---------------- reversing ----------------
    ("reversing", "gets() import, no proven overflow", {"imports": ["gets"]}, False, "CWE-242", "hard",
     "Banned function present but no demonstrated reachable overflow."),
    ("reversing", "system() with tainted string evidence",
     {"imports": ["system"], "strings": ["/bin/sh -c %s"]}, True, "CWE-78", "medium",
     "Command sink with format string suggests injection path."),
    ("reversing", "Hardcoded private key string",
     {"strings": ["-----BEGIN RSA PRIVATE KEY-----"]}, True, "CWE-321", "medium",
     "Embedded private key extractable from the binary."),
    ("reversing", "Only benign imports", {"imports": ["printf", "malloc"]}, False, "CWE-noinfo", "easy",
     "No dangerous sinks."),
    # ---------------- social ----------------
    ("social", "No SPF and no DMARC", {"spf": False, "dmarc": False}, True, "CWE-290", "easy",
     "Domain trivially spoofable for phishing (authorized assessment)."),
    ("social", "DMARC p=none", {"dmarc": True, "dmarc_policy": "none"}, True, "CWE-290", "medium",
     "Monitoring only; spoofed mail still delivered."),
    ("social", "DMARC p=reject, SPF, DKIM", {"spf": True, "dkim": True, "dmarc": True,
     "dmarc_policy": "reject"}, False, "CWE-290", "medium", "Enforced; spoofing blocked."),
    ("social", "Look-alike domain registered", {"lookalike_registered": True, "spf": True, "dmarc": True,
     "dmarc_policy": "reject"}, True, "CWE-290", "hard",
     "Even with enforcement, a registered look-alike enables convincing phishing."),
    # ---------------- recon ----------------
    ("recon", "admin subdomain discovered", {"host": "admin.example.com"}, False, "CWE-noinfo", "hard",
     "Interesting attack surface but discovery alone is not exploitable."),
    ("recon", "bare IP asset", {"url": "http://203.0.113.10/"}, False, "CWE-noinfo", "easy",
     "Asset enumeration signal, not a vulnerability."),
]


def build() -> list[dict]:
    counters: dict[str, int] = {}
    out = []
    for topic, title, state, truth, cwe, difficulty, rationale in CASES:
        counters[topic] = counters.get(topic, 0) + 1
        target = _target_for(topic, counters[topic])
        # Ground each case in the taxonomy via the same pipeline Raze uses.
        vc = infer_class(topic, analyze(topic, state))
        out.append(
            {
                "finding": {
                    "target": target,
                    "topic": topic,
                    "title": title,
                    "has_reproduction": bool(truth),
                    "state": state,
                },
                "exploitable_truth": truth,
                "cwe": cwe,
                "vuln_class": vc.id if vc else None,
                "cvss_vector": vc.typical_cvss if vc else None,
                "cvss_score": vc.typical_score if vc else None,
                "difficulty": difficulty,
                "label_rationale": rationale,
            }
        )
    return out


def _target_for(topic: str, idx: int) -> str:
    base = {
        "web": "app{n}.example.com",
        "network": "host{n}.example.com",
        "crypto": "svc{n}.example.com",
        "ad": "dc{n}.corp.example.com",
        "cloud": "cloud{n}.example.com",
        "mobile": "com.example.app{n}",
        "wireless": "AP-Corp-{n}",
        "exploitdev": "bin{n}.example.com",
        "reversing": "fw{n}.example.com",
        "social": "example{n}.com",
        "recon": "asset{n}.example.com",
    }[topic]
    return base.format(n=idx)


def main() -> int:
    data = build()
    path = os.path.join(os.path.dirname(__file__), "offsec_dataset.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    pos = sum(1 for c in data if c["exploitable_truth"])
    print(f"wrote {len(data)} cases ({pos} exploitable / {len(data) - pos} not) to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
