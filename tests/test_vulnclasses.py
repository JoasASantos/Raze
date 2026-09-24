"""Vulnerability-class taxonomy tests."""

from raze.cvss import base_score
from raze.judgments import Severity
from raze.topics.taxonomy import ALL_TOPICS
from raze.vulnclasses import CLASSES, by_cwe, by_topic, get


def test_registry_nontrivial_and_ids_consistent():
    assert len(CLASSES) >= 30
    for cid, c in CLASSES.items():
        assert c.id == cid
        assert c.cwe and all(x.startswith("CWE-") for x in c.cwe)
        assert c.topic in ALL_TOPICS


def test_typical_vectors_are_valid_and_scored():
    for c in CLASSES.values():
        score = base_score(c.typical_cvss)
        assert 0.0 <= score <= 10.0
        assert isinstance(c.typical_severity, Severity)


def test_sqli_is_critical_and_web():
    sqli = get("sqli")
    assert sqli.topic == "web"
    assert "CWE-89" in sqli.cwe
    assert sqli.typical_severity == Severity.critical


def test_lookup_by_cwe_and_topic():
    assert any(c.id == "ssrf" for c in by_cwe("CWE-918"))
    assert all(c.topic == "ad" for c in by_topic("ad"))
    assert {c.id for c in by_topic("ad")} >= {"kerberoasting", "unconstrained_delegation"}


def test_every_topic_has_at_least_one_class():
    covered = {c.topic for c in CLASSES.values()}
    # recon is discovery-only; every other topic should have a class.
    assert set(ALL_TOPICS) - covered <= {"recon"}
