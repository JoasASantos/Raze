"""Tests for the deterministic validator gate — the blocking conditions must hold
regardless of model probability."""

from offsec_one.validators import validate_finding
from raze.judgments import ExploitVerdict, NoveltyClass


def test_exploitable_without_repro_is_blocked():
    r = validate_finding(
        verdict=ExploitVerdict.exploitable,
        probability=0.99,  # high confidence must not override missing PoC
        reachable=True,
        novelty=NoveltyClass.novel,
        has_reproduction=False,
    )
    assert not r.accepted and r.disposition == "blocked"


def test_not_reachable_is_blocked():
    r = validate_finding(
        verdict=ExploitVerdict.conditional,
        probability=0.9,
        reachable=False,
        novelty=NoveltyClass.novel,
        has_reproduction=True,
    )
    assert not r.accepted and r.disposition == "blocked"


def test_duplicate_is_dropped():
    r = validate_finding(
        verdict=ExploitVerdict.conditional,
        probability=0.9,
        reachable=True,
        novelty=NoveltyClass.duplicate,
        has_reproduction=True,
    )
    assert r.disposition == "dropped"


def test_low_probability_is_held():
    r = validate_finding(
        verdict=ExploitVerdict.conditional,
        probability=0.3,
        reachable=True,
        novelty=NoveltyClass.novel,
        has_reproduction=True,
    )
    assert r.disposition == "held"


def test_clean_finding_is_queued():
    r = validate_finding(
        verdict=ExploitVerdict.exploitable,
        probability=0.85,
        reachable=True,
        novelty=NoveltyClass.novel,
        has_reproduction=True,
    )
    assert r.accepted and r.disposition == "queued"
