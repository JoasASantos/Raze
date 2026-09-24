"""Engagement orchestration tests."""

import pytest

from raze import Raze, RazeAgent
from raze.agent import Finding
from raze.decide import Decision
from raze.engagement import _correlate, run_engagement


def _agent():
    return RazeAgent(raze=Raze())  # echo backend


def test_engagement_reports_timing_and_ranking():
    findings = [
        Finding(target="a.example.com", topic="web", title=f"f{i}") for i in range(5)
    ]
    report = run_engagement(findings, _agent())
    assert report.n_findings == 5
    assert report.throughput > 0
    # ranked descending by priority
    prios = [d.priority for d in report.decisions]
    assert prios == sorted(prios, reverse=True)
    assert sum(report.action_counts.values()) == 5


def test_empty_engagement_raises():
    with pytest.raises(ValueError):
        run_engagement([], _agent())


def _dec(target_title, action, priority):
    return Decision(
        finding_title=target_title, action=action, priority=priority, confidence=0.9,
        factors={}, signals=[], rationale="",
    )


def test_correlate_boosts_multiple_actionable_on_one_target():
    findings = [
        Finding(target="t.example.com", topic="web", title="x1"),
        Finding(target="t.example.com", topic="network", title="x2"),
        Finding(target="other.example.com", topic="web", title="y1"),
    ]
    decisions = [
        _dec("x1", "queue", 60.0),
        _dec("x2", "exploit-now", 80.0),
        _dec("y1", "queue", 55.0),
    ]
    chains = _correlate(findings, decisions)
    assert len(chains) == 1
    assert chains[0].target == "t.example.com"
    # both actionable decisions on t.example.com got the compounding bonus
    assert decisions[0].priority == 65.0
    assert decisions[1].priority == 85.0
    # single-actionable target is not chained
    assert decisions[2].priority == 55.0
