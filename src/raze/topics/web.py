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
