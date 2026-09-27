"""Tests for the recall-raising detectors (SSRF, password-hash, primitive, etc.)."""

from raze.topics.crypto import WeakAlgorithmAnalyzer
from raze.topics.exploitdev import MitigationAnalyzer
from raze.topics.reversing import BinaryTriageAnalyzer
from raze.topics.web import SSRFAnalyzer


def _names(sigs):
    return {s.name for s in sigs}


def test_ssrf_internal_host():
    assert "ssrf" in _names(SSRFAnalyzer().analyze({"param_value": "http://127.0.0.1:8080/admin"}))
    assert "ssrf" in _names(SSRFAnalyzer().analyze({"param_value": "http://169.254.169.254/"}))


def test_ssrf_external_host_ignored():
    assert SSRFAnalyzer().analyze({"param_value": "https://api.stripe.com/v1/charges"}) == []
    assert SSRFAnalyzer().analyze({"param_value": "not a url"}) == []


def test_weak_password_hash_high():
    sigs = WeakAlgorithmAnalyzer().analyze({"algorithms": ["md5"], "context": "password-storage"})
    assert any(s.name == "weak-password-hash" and s.severity == "high" for s in sigs)


def test_md5_non_password_stays_weak_algorithm():
    sigs = WeakAlgorithmAnalyzer().analyze({"algorithms": ["md5"]})
    assert "weak-algorithm" in _names(sigs) and "weak-password-hash" not in _names(sigs)


def test_known_overflow_primitive_critical():
    sigs = MitigationAnalyzer().analyze({"nx": False, "canary": False, "has_known_overflow": True})
    assert any(s.name == "exploitable-primitive" and s.severity == "critical" for s in sigs)


def test_embedded_private_key():
    sigs = BinaryTriageAnalyzer().analyze({"strings": ["-----BEGIN RSA PRIVATE KEY-----"]})
    assert "embedded-secret" in _names(sigs)


def test_command_injection_evidence():
    sigs = BinaryTriageAnalyzer().analyze({"imports": ["system"], "strings": ["/bin/sh -c %s"]})
    assert "command-injection-evidence" in _names(sigs)


def test_gets_without_evidence_no_injection_signal():
    sigs = BinaryTriageAnalyzer().analyze({"imports": ["gets"]})
    assert "command-injection-evidence" not in _names(sigs)
