"""Active-tool tests: authorization gate + HeaderFetchTool (urlopen mocked)."""

import email.message

import pytest

from raze.authz import Scope, ScopeError
from raze.tools import HeaderFetchTool
from raze.topics.web import OpenRedirectAnalyzer, SQLiErrorAnalyzer


class _FakeResp:
    def __init__(self, headers, status=200):
        self.headers = headers
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_active_tool_requires_scope():
    tool = HeaderFetchTool()
    with pytest.raises(ScopeError):
        tool.run("app.example.com", None)


def test_active_tool_blocks_out_of_scope():
    tool = HeaderFetchTool()
    scope = Scope("E", "R", ["*.example.com"])
    with pytest.raises(ScopeError):
        tool.run("evil.other.com", scope)


def test_header_fetch_returns_headers(monkeypatch):
    scope = Scope("E", "R", ["*.example.com"])
    msg = email.message.Message()
    msg["Server"] = "nginx"
    msg["X-Frame-Options"] = "DENY"

    def fake_urlopen(req, timeout=None):
        return _FakeResp(msg, status=200)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    state = HeaderFetchTool().run("app.example.com", scope)
    assert state["status"] == 200
    assert state["url"].startswith("https://")
    assert state["response_headers"]["Server"] == "nginx"


def test_header_fetch_rejects_non_http():
    scope = Scope("E", "R", ["*"])
    with pytest.raises(ValueError):
        HeaderFetchTool().run("file:///etc/passwd", scope)


def test_sqli_error_detected():
    sigs = SQLiErrorAnalyzer().analyze(
        {"response_body": "Warning: you have an error in your SQL syntax near ..."}
    )
    assert any(s.name == "sql-error" and s.severity == "high" for s in sigs)


def test_open_redirect_detected():
    sigs = OpenRedirectAnalyzer().analyze(
        {"location_header": "https://evil.example/", "param_value": "https://evil.example/"}
    )
    assert any(s.name == "open-redirect" for s in sigs)


def test_open_redirect_ignores_internal_path():
    assert OpenRedirectAnalyzer().analyze(
        {"location_header": "/dashboard", "param_value": "/dashboard"}
    ) == []
