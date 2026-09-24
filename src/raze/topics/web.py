"""Web application analyzers.

Deterministic detectors over already-collected HTTP data. They never send
requests — the harness collects responses under scope and passes them here.
"""

from __future__ import annotations

import html
import re

from raze.topics.base import Signal

DANGEROUS_CHARS = ("<", ">", '"', "'", "(", ")")

_SECURITY_HEADERS = {
    "content-security-policy": ("medium", "no Content-Security-Policy"),
    "strict-transport-security": ("medium", "no HSTS (Strict-Transport-Security)"),
    "x-frame-options": ("low", "no X-Frame-Options (clickjacking)"),
    "x-content-type-options": ("low", "no X-Content-Type-Options: nosniff"),
}


class ReflectionAnalyzer:
    """Detect unescaped reflection of an input value in a response body (XSS signal).

    state: {"param_value": str, "response_body": str}
    """

    topic = "web"

    def analyze(self, state: dict) -> list[Signal]:
        value = state.get("param_value")
        body = state.get("response_body")
        if not value or not body or value not in body:
            return []
        signals = [Signal("reflection", f"input {value!r} reflected in response body")]
        escaped = html.escape(value, quote=True)
        raw_dangerous = [c for c in DANGEROUS_CHARS if c in value]
        if raw_dangerous and escaped not in body:
            signals.append(
                Signal(
                    "unescaped-reflection",
                    f"dangerous chars {raw_dangerous} reflected without HTML-encoding",
                    severity="high",
                )
            )
        return signals


_SQL_ERROR = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|psql:|SQLite3::|"
    r"Unclosed quotation mark|Microsoft OLE DB Provider for SQL Server|"
    r"You have an error in your SQL syntax)",
    re.IGNORECASE,
)


class SQLiErrorAnalyzer:
    """Detect SQL error messages leaking into a response body (error-based SQLi).

    state: {"response_body": str}
    """

    topic = "web"

    def analyze(self, state: dict) -> list[Signal]:
        body = state.get("response_body")
        if not body:
            return []
        m = _SQL_ERROR.search(body)
        if m:
            return [Signal("sql-error", f"SQL error string in response: {m.group(0)!r}", severity="high")]
        return []


class OpenRedirectAnalyzer:
    """Detect a redirect whose Location is driven by user input (open redirect).

    state: {"location_header": str, "param_value": str}
    """

    topic = "web"

    def analyze(self, state: dict) -> list[Signal]:
        loc = state.get("location_header")
        pv = state.get("param_value")
        if not loc or not pv or pv not in loc:
            return []
        if loc.lower().startswith(("http://", "https://", "//")):
            return [
                Signal("open-redirect", f"Location reflects input to external target: {loc!r}", severity="medium")
            ]
        return []


class SecurityHeaderAnalyzer:
    """Flag missing security response headers.

    state: {"response_headers": {name: value}}  (names matched case-insensitively)
    """

    topic = "web"

    def analyze(self, state: dict) -> list[Signal]:
        headers = state.get("response_headers")
        if not isinstance(headers, dict):
            return []
        present = {k.lower() for k in headers}
        out: list[Signal] = []
        for header, (severity, detail) in _SECURITY_HEADERS.items():
            if header not in present:
                out.append(Signal("missing-header", detail, severity=severity))
        return out


class CorsMisconfigAnalyzer:
    """Detect a dangerous CORS policy.

    state: {"cors_acao": str, "cors_credentials": bool, "cors_reflects_origin": bool}
    """

    topic = "web"

    def analyze(self, state: dict) -> list[Signal]:
        acao = state.get("cors_acao")
        if not acao:
            return []
        creds = bool(state.get("cors_credentials"))
        if acao == "*" and creds:
            return [Signal("cors-misconfig", "ACAO=* with credentials", severity="high")]
        if state.get("cors_reflects_origin"):
            sev = "high" if creds else "medium"
            detail = "origin reflected" + (" with credentials" if creds else "")
            return [Signal("cors-misconfig", detail, severity=sev)]
        if acao == "*":
            return [Signal("cors-misconfig", "ACAO wildcard", severity="medium")]
        return []


class ClickjackingAnalyzer:
    """Flag pages with no framing protection.

    state: {"response_headers": {name: value}}
    """

    topic = "web"

    def analyze(self, state: dict) -> list[Signal]:
        headers = state.get("response_headers")
        if not isinstance(headers, dict):
            return []
        present = {k.lower(): str(v) for k, v in headers.items()}
        has_xfo = "x-frame-options" in present
        frame_ancestors = "frame-ancestors" in present.get("content-security-policy", "").lower()
        if not has_xfo and not frame_ancestors:
            return [Signal("clickjacking", "no X-Frame-Options and no CSP frame-ancestors", "low")]
        return []


class CookieSecurityAnalyzer:
    """Flag session cookies missing security attributes.

    state: {"set_cookie": "name=v; Path=/; ..."}
    """

    topic = "web"

    def analyze(self, state: dict) -> list[Signal]:
        cookie = state.get("set_cookie")
        if not cookie:
            return []
        low = cookie.lower()
        missing = [flag for flag in ("httponly", "secure") if flag not in low]
        if "samesite" not in low:
            missing.append("samesite")
        if not missing:
            return []
        sev = "medium" if ("httponly" in missing or "secure" in missing) else "low"
        return [Signal("insecure-cookie", "Set-Cookie missing " + ", ".join(missing), sev)]
