"""Topic analyzer tests — deterministic detectors over collected data."""

from raze.topics import analyze
from raze.topics.cloud import BucketExposureAnalyzer, MetadataSSRFAnalyzer
from raze.topics.crypto import SecretEntropyAnalyzer, WeakAlgorithmAnalyzer, shannon_entropy
from raze.topics.network import PortExposureAnalyzer
from raze.topics.recon import AssetAnalyzer
from raze.topics.web import ReflectionAnalyzer, SecurityHeaderAnalyzer


def _names(signals):
    return {s.name for s in signals}


def test_reflection_unescaped_flags_high():
    signals = ReflectionAnalyzer().analyze(
        {"param_value": "<script>", "response_body": "x <script> y"}
    )
    assert "unescaped-reflection" in _names(signals)
    assert any(s.severity == "high" for s in signals)


def test_reflection_escaped_not_flagged_high():
    signals = ReflectionAnalyzer().analyze(
        {"param_value": "<script>", "response_body": "x &lt;script&gt; and raw <script>"}
    )
    # Escaped form present -> only the plain reflection signal, no unescaped-high.
    assert "unescaped-reflection" not in _names(signals)


def test_reflection_absent_returns_empty():
    assert ReflectionAnalyzer().analyze({"param_value": "abc", "response_body": "nothing"}) == []


def test_missing_security_headers():
    signals = SecurityHeaderAnalyzer().analyze({"response_headers": {"Server": "nginx"}})
    assert "missing-header" in _names(signals)
    assert len(signals) == 4


def test_recon_interesting_subdomain():
    signals = AssetAnalyzer().analyze({"host": "admin.example.com"})
    assert "interesting-subdomain" in _names(signals)


def test_recon_bare_ip():
    signals = AssetAnalyzer().analyze({"url": "http://10.0.0.5/x"})
    assert "bare-ip" in _names(signals)


def test_network_risky_port_redis_critical():
    signals = PortExposureAnalyzer().analyze({"open_ports": [22, 6379, 80]})
    assert any(s.severity == "critical" and "6379" in s.detail for s in signals)


def test_cloud_public_bucket():
    signals = BucketExposureAnalyzer().analyze({"bucket_acl": {"grants": ["AllUsers"]}})
    assert "public-bucket" in _names(signals)


def test_cloud_metadata_ssrf_critical():
    signals = MetadataSSRFAnalyzer().analyze({"url": "http://169.254.169.254/latest/meta-data/"})
    assert any(s.severity == "critical" for s in signals)


def test_crypto_weak_and_jwt_none():
    signals = WeakAlgorithmAnalyzer().analyze({"algorithms": ["MD5", "AES-256-GCM"], "jwt_alg": "none"})
    names = _names(signals)
    assert "weak-algorithm" in names and "jwt-alg-none" in names


def test_crypto_low_entropy_secret():
    assert shannon_entropy("aaaaaa") == 0.0
    signals = SecretEntropyAnalyzer().analyze({"secret": "aaaaaaaa"})
    assert "low-entropy-secret" in _names(signals)


def test_registry_dispatch():
    signals = analyze("network", {"open_ports": [27017]})
    assert any(s.severity == "critical" for s in signals)
    assert analyze("mobile", {}) == []  # declared but no analyzer yet
