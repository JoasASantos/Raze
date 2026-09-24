"""Tests for the CORS / clickjacking / cookie analyzers and new classify maps."""

from raze.classify import infer_class
from raze.topics.base import Signal
from raze.topics.web import (
    ClickjackingAnalyzer,
    CookieSecurityAnalyzer,
    CorsMisconfigAnalyzer,
)


def _names(sigs):
    return {s.name for s in sigs}


def test_cors_wildcard_with_credentials_high():
    sigs = CorsMisconfigAnalyzer().analyze({"cors_acao": "*", "cors_credentials": True})
    assert any(s.name == "cors-misconfig" and s.severity == "high" for s in sigs)


def test_cors_reflected_origin():
    sigs = CorsMisconfigAnalyzer().analyze(
        {"cors_acao": "https://evil.example", "cors_reflects_origin": True, "cors_credentials": True}
    )
    assert "cors-misconfig" in _names(sigs)


def test_cors_absent_returns_empty():
    assert CorsMisconfigAnalyzer().analyze({}) == []


def test_clickjacking_when_no_framing_protection():
    sigs = ClickjackingAnalyzer().analyze({"response_headers": {"Server": "nginx"}})
    assert "clickjacking" in _names(sigs)


def test_clickjacking_suppressed_by_xfo():
    assert ClickjackingAnalyzer().analyze(
        {"response_headers": {"X-Frame-Options": "DENY"}}
    ) == []


def test_clickjacking_suppressed_by_csp_frame_ancestors():
    assert ClickjackingAnalyzer().analyze(
        {"response_headers": {"Content-Security-Policy": "frame-ancestors 'none'"}}
    ) == []


def test_cookie_missing_flags():
    sigs = CookieSecurityAnalyzer().analyze({"set_cookie": "sid=abc; Path=/"})
    assert "insecure-cookie" in _names(sigs)


def test_cookie_secure_httponly_samesite_ok():
    assert CookieSecurityAnalyzer().analyze(
        {"set_cookie": "sid=abc; HttpOnly; Secure; SameSite=Strict"}
    ) == []


def test_classify_new_signals():
    assert infer_class("web", [Signal("cors-misconfig", "x", "high")]).id == "cors_misconfig"
    assert infer_class("web", [Signal("clickjacking", "x", "low")]).id == "clickjacking"
    assert infer_class("web", [Signal("insecure-cookie", "x", "medium")]).id == "weak_session"
