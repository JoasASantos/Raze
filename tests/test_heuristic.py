"""Deterministic HeuristicBackend tests + benchmark accuracy vs echo."""

import json
from pathlib import Path

from raze import Raze, RazeAgent
from raze.agent import Finding
from raze.backends import make_backend
from raze.backends.heuristic import HeuristicBackend
from raze.bench import BenchCase, run
from raze.judgments import CombinedJudgment, ExploitVerdict, JudgmentContext

DATASET = Path(__file__).resolve().parents[1] / "benchmarks" / "offsec_dataset.json"


def _combined(topic, state):
    return Raze(backend=HeuristicBackend()).judge(
        CombinedJudgment, JudgmentContext(task="t", topic=topic, state=state)
    )


def test_factory_and_registry():
    assert isinstance(make_backend("heuristic"), HeuristicBackend)


def test_sql_error_is_exploitable():
    j = _combined("web", {"response_body": "You have an error in your SQL syntax"})
    assert j.verdict == ExploitVerdict.exploitable
    assert j.reachable and j.severity.value in ("high", "critical")


def test_missing_headers_only_not_exploitable():
    j = _combined("web", {"response_headers": {"Server": "nginx"}})
    assert j.verdict != ExploitVerdict.exploitable  # hardening signal alone


def test_no_signals_conservative():
    j = _combined("web", {})
    assert j.verdict == ExploitVerdict.not_exploitable
    assert not j.reachable


def test_redis_exposed_exploitable():
    j = _combined("network", {"open_ports": [6379]})
    assert j.verdict == ExploitVerdict.exploitable


def test_agent_decide_with_heuristic_acts():
    agent = RazeAgent(raze=Raze(backend=HeuristicBackend()))
    d = agent.decide(Finding(target="db.example.com", topic="network", title="Redis",
                             has_reproduction=True, state={"open_ports": [6379]}))
    assert d.action in ("exploit-now", "queue")
    assert d.vuln_class == "unauth_service"


def _load_cases():
    raw = json.loads(DATASET.read_text(encoding="utf-8"))
    return [
        BenchCase(Finding(**e["finding"]), exploitable_truth=bool(e["exploitable_truth"]))
        for e in raw
    ]


def test_heuristic_beats_echo_on_dataset():
    cases = _load_cases()
    echo = run(cases, lambda: RazeAgent(raze=Raze()), runs=2)
    heur = run(cases, lambda: RazeAgent(raze=Raze(backend=HeuristicBackend())), runs=2)
    assert heur.metrics["accuracy"] > echo.metrics["accuracy"]
    assert heur.metrics["accuracy"] >= 0.75  # deterministic, no LLM
    assert heur.metrics["recall"] > 0.0  # echo had 0 recall
