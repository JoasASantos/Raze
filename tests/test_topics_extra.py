"""Tests for the ad/mobile/wireless/exploitdev/reversing/social analyzers."""

from offsec_one.topics import ANALYZERS, PROPOSED_TOPICS, analyze
from offsec_one.topics.ad import DelegationAnalyzer, KerberoastingAnalyzer
from offsec_one.topics.exploitdev import MitigationAnalyzer
from offsec_one.topics.mobile import AndroidManifestAnalyzer
from offsec_one.topics.reversing import BinaryTriageAnalyzer
from offsec_one.topics.social import EmailSpoofabilityAnalyzer
from offsec_one.topics.wireless import WifiSecurityAnalyzer
from raze.topics import ALL_TOPICS


def _names(sigs):
    return {s.name for s in sigs}


def test_ad_kerberoast_admin_is_high():
    sigs = KerberoastingAnalyzer().analyze({"accounts": [{"name": "svc", "spn": True, "admin": True}]})
    assert any(s.name == "kerberoastable" and s.severity == "high" for s in sigs)


def test_ad_unconstrained_delegation_critical():
    sigs = DelegationAnalyzer().analyze({"accounts": [{"name": "srv", "unconstrained_delegation": True}]})
    assert any(s.severity == "critical" for s in sigs)


def test_mobile_debuggable_high():
    sigs = AndroidManifestAnalyzer().analyze({"debuggable": True, "cleartext_traffic": True})
    assert "debuggable" in _names(sigs) and "cleartext-traffic" in _names(sigs)


def test_wireless_open_critical_and_wps():
    sigs = WifiSecurityAnalyzer().analyze({"encryption": "open", "wps_enabled": True})
    assert any(s.severity == "critical" for s in sigs)
    assert "wps-enabled" in _names(sigs)


def test_exploitdev_missing_mitigations():
    sigs = MitigationAnalyzer().analyze({"nx": False, "canary": False, "relro": "none"})
    assert {"no-nx", "no-canary", "weak-relro"} <= _names(sigs)


def test_reversing_dangerous_import_and_string():
    sigs = BinaryTriageAnalyzer().analyze(
        {"imports": ["gets", "printf"], "strings": ["db_password=hunter2"]}
    )
    assert any(s.name == "dangerous-import" and s.severity == "critical" for s in sigs)
    assert "interesting-string" in _names(sigs)


def test_social_spoofable_domain():
    sigs = EmailSpoofabilityAnalyzer().analyze({"spf": False, "dmarc": False})
    assert {"no-spf", "no-dmarc"} <= _names(sigs)


def test_every_taxonomy_topic_has_an_analyzer():
    assert PROPOSED_TOPICS == []
    assert set(ALL_TOPICS) <= set(ANALYZERS), set(ALL_TOPICS) - set(ANALYZERS)


def test_registry_dispatch_ad():
    sigs = analyze("ad", {"accounts": [{"name": "u", "asrep": True}]})
    assert "asrep-roastable" in _names(sigs)
