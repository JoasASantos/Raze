"""Rule-based cross-class attack chaining tests."""

from raze.chaining import CHAIN_RULES, detect_class_chains
from raze.decide import Decision


def _dec(title, vuln_class, priority=60.0):
    return Decision(
        finding_title=title, action="queue", priority=priority, confidence=0.9,
        factors={}, signals=[], rationale="", vuln_class=vuln_class,
    )


def test_ad_domain_compromise_chain_fires():
    decisions = [
        _dec("roast svc", "kerberoasting", 60.0),
        _dec("deleg srv", "unconstrained_delegation", 70.0),
        _dec("unrelated", "xss_reflected", 30.0),
    ]
    chains = detect_class_chains(decisions)
    assert any(c.label == "ad-domain-compromise" for c in chains)
    # members got the rule bonus (15.0)
    assert decisions[0].priority == 75.0
    assert decisions[1].priority == 85.0
    # non-member untouched
    assert decisions[2].priority == 30.0


def test_single_stage_does_not_fire():
    decisions = [_dec("only ssrf", "ssrf", 60.0)]
    assert detect_class_chains(decisions) == []


def test_chain_priority_is_boosted_max():
    decisions = [
        _dec("svc", "unauth_service", 80.0),
        _dec("rce", "rce", 90.0),
    ]
    chains = detect_class_chains(decisions)
    assert chains[0].label == "exposed-service-to-rce"
    assert chains[0].chain_priority == 100.0  # 90 + 12 capped at 100


def test_rules_are_well_formed():
    for r in CHAIN_RULES:
        assert len(r.stages) >= 2
        assert r.min_stages >= 2
        assert r.goal
