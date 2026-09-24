"""Class inference + class-adapted decision tests."""

from raze.classify import infer_class
from raze.decide import build_decision
from raze.judgments import CombinedJudgment, ExploitVerdict, NoveltyClass, Severity
from raze.topics.base import Signal
from raze.validators import validate_finding
from raze.vulnclasses import get


def test_infer_from_strongest_signal():
    signals = [
        Signal("missing-header", "no CSP", "medium"),
        Signal("sql-error", "SQL syntax", "high"),
    ]
    vc = infer_class("web", signals)
    assert vc.id == "sqli"  # high-severity signal wins


def test_infer_topic_fallback_when_no_signal_match():
    vc = infer_class("crypto", [])
    assert vc is not None and vc.topic == "crypto"


def test_infer_jwt_none():
    assert infer_class("crypto", [Signal("jwt-alg-none", "x", "critical")]).id == "jwt_flaw"


def _combined(severity=Severity.info):
    return CombinedJudgment(
        probability=0.9, rationale="", verdict=ExploitVerdict.exploitable,
        reachable=True, novelty=NoveltyClass.novel, severity=severity,
    )


def test_class_seeds_severity_and_cwe():
    j = _combined(severity=Severity.info)  # model unsure on severity
    v = validate_finding(verdict=j.verdict, probability=j.probability, reachable=True,
                         novelty=j.novelty, has_reproduction=True)
    d = build_decision(
        finding_title="t", judgment=j, signals=[], validation=v,
        has_reproduction=True, vuln_class=get("sqli"),
    )
    assert d.vuln_class == "sqli"
    assert "CWE-89" in d.cwe
    assert d.cvss_score and d.cvss_score >= 9.0
    assert d.severity == "critical"  # seeded from class CVSS, not left at info
    assert d.priority >= 75.0


def test_class_never_downgrades_model_severity():
    j = _combined(severity=Severity.critical)
    v = validate_finding(verdict=j.verdict, probability=j.probability, reachable=True,
                         novelty=j.novelty, has_reproduction=True)
    d = build_decision(
        finding_title="t", judgment=j, signals=[], validation=v,
        has_reproduction=True, vuln_class=get("open_redirect"),  # typical low
    )
    assert d.severity == "critical"  # model's higher severity kept
