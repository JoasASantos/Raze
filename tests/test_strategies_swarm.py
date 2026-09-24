"""Strategy generation + swarm loop tests."""

from raze import Raze, RazeAgent
from raze.agent import Finding
from raze.strategies import generate
from raze.swarm import build_strategies, run_swarm


def test_generate_known_class_has_prereq_chain():
    strats = generate("kerberoast svc", "kerberoasting", uid="0")
    ids = [s.id for s in strats]
    assert any("roast" in i for i in ids) and any("crack" in i for i in ids)
    crack = next(s for s in strats if s.id.endswith(":crack"))
    assert crack.prerequisites == ["tgs_hash"]  # depends on the roast yield


def test_generate_unknown_class_fallback():
    strats = generate("x", None)
    assert len(strats) == 1 and strats[0].description.startswith("attempt")


def test_swarm_runs_and_accumulates_signal():
    findings = [
        Finding(target="db.example.com", topic="network", title="Redis",
                state={"open_ports": [6379]}),
        Finding(target="app.example.com", topic="web", title="SQLi",
                state={"response_body": "SQL syntax error"}),
    ]
    strategies = build_strategies(findings, RazeAgent(raze=Raze()))
    assert strategies
    report = run_swarm(strategies)
    assert report.n_strategies == len(strategies)
    assert report.trajectory  # at least one runnable strategy landed
    # signal accumulated for landed classes
    assert sum(report.signal.values()) >= 1


def test_swarm_unlocks_dependent_via_yields():
    # unauth_service: 'access' yields service_access, unlocking 'rce'.
    findings = [Finding(target="h.example.com", topic="network", title="Redis",
                        state={"open_ports": [6379]})]
    strategies = build_strategies(findings, RazeAgent(raze=Raze()))
    report = run_swarm(strategies)
    landed_suffixes = [s.strategy_id.split(":")[-1] for s in report.trajectory]
    # both the access step and the unlocked rce step should have run
    assert "access" in landed_suffixes
    assert "shell" in report.discovered


def test_swarm_steps_limit():
    findings = [Finding(target="a.example.com", topic="web", title="SQLi",
                        state={"response_body": "SQL syntax error"})]
    strategies = build_strategies(findings, RazeAgent(raze=Raze()))
    report = run_swarm(strategies, steps=1)
    assert len(report.trajectory) == 1
