"""Decision engine tests — chained, multi-factor, decisive."""

from raze import Raze, RazeAgent
from raze.agent import Finding
from raze.decide import build_decision
from raze.judgments import CombinedJudgment, ExploitVerdict, NoveltyClass, Severity
from raze.topics.base import Signal
from raze.validators import validate_finding


def _combined(**kw):
    base = {
        "probability": 0.9,
        "rationale": "",
        "verdict": ExploitVerdict.exploitable,
        "reachable": True,
        "novelty": NoveltyClass.novel,
        "severity": Severity.critical,
    }
    base.update(kw)
    return CombinedJudgment(**base)


def _decision_for(judgment, has_reproduction=True, signals=None):
    v = validate_finding(
        verdict=judgment.verdict,
        probability=judgment.probability,
        reachable=judgment.reachable,
        novelty=judgment.novelty,
        has_reproduction=has_reproduction,
    )
    return build_decision(
        finding_title="t",
        judgment=judgment,
        signals=signals or [],
        validation=v,
        has_reproduction=has_reproduction,
    )


def test_high_exploitable_is_exploit_now():
    d = _decision_for(_combined())
    assert d.action == "exploit-now"
    assert d.priority >= 75.0
    assert d.confidence == 0.9


def test_unreachable_is_blocked():
    d = _decision_for(_combined(reachable=False))
    assert d.action == "blocked"


def test_duplicate_is_dropped():
    d = _decision_for(_combined(novelty=NoveltyClass.duplicate))
    assert d.action == "drop"


def test_low_severity_not_exploitable_investigate():
    d = _decision_for(
        _combined(verdict=ExploitVerdict.conditional, severity=Severity.low), has_reproduction=True
    )
    assert d.action in ("investigate", "queue")
    assert d.action == "investigate"  # low severity * conditional stays under 50


def test_signal_boost_raises_priority():
    low = _decision_for(_combined(severity=Severity.medium), signals=[])
    high = _decision_for(
        _combined(severity=Severity.medium), signals=[Signal("x", "y", severity="critical")]
    )
    assert high.priority > low.priority


def test_agent_decide_is_single_call_with_latency():
    agent = RazeAgent(raze=Raze())  # echo backend
    d = agent.decide(Finding(target="a.example.com", topic="web", title="t"))
    assert d.latency_ms is not None
    # Echo is conservative (not reachable) -> blocked.
    assert d.action == "blocked"


def test_decision_to_dict_serializable():
    import json

    json.dumps(_decision_for(_combined()).to_dict())
