"""Swarm driver: findings -> candidate strategies -> adaptive fast-pass loop.

Ties the pieces together: decide each finding (to get its vulnerability class),
generate candidate attack strategies, then run the adaptive scorer's loop. The
loop picks the highest-scored runnable strategy, "executes" it via an oracle
(the operator/exploration agent in production; a simulated one here), updates the
live state + signal, and re-ranks — so attention follows what lands.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

from raze.adaptive import AdaptiveEngagement, Strategy
from raze.agent import Finding, RazeAgent
from raze.strategies import generate


@dataclass
class SwarmStep:
    strategy_id: str
    vuln_class: str | None
    score: float
    success: bool


@dataclass
class SwarmReport:
    n_strategies: int
    total_ms: float
    initial_ranking: list[dict]
    trajectory: list[SwarmStep]
    discovered: list[str]
    signal: dict
    unreached: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "n_strategies": self.n_strategies,
            "total_ms": round(self.total_ms, 2),
            "initial_ranking": self.initial_ranking,
            "trajectory": [asdict(s) for s in self.trajectory],
            "discovered": sorted(self.discovered),
            "signal": self.signal,
            "unreached": self.unreached,
        }


def build_strategies(findings: list[Finding], agent: RazeAgent) -> list[Strategy]:
    strategies: list[Strategy] = []
    for i, finding in enumerate(findings):
        decision = agent.decide(finding)  # scope-gated; yields the vuln class
        strategies.extend(generate(finding.title, decision.vuln_class, uid=str(i)))
    return strategies


def run_swarm(
    strategies: list[Strategy],
    *,
    steps: int | None = None,
    oracle: Callable[[Strategy], bool] | None = None,
) -> SwarmReport:
    """Run the adaptive loop. `oracle(strategy) -> landed?` simulates execution;
    the default assumes a runnable pick lands (to demonstrate unlock + signal)."""
    eng = AdaptiveEngagement()
    oracle = oracle or (lambda _s: True)

    initial = [s.to_dict() for s in eng.rank(strategies)]
    remaining = list(strategies)
    trajectory: list[SwarmStep] = []
    max_steps = steps if steps is not None else len(strategies)

    t0 = time.perf_counter()
    for _ in range(max_steps):
        best = eng.next_best(remaining)
        if best is None or not best.runnable:
            break  # nothing runnable given the current live state
        landed = oracle(best.strategy)
        eng.report_result(best.strategy, landed)
        trajectory.append(
            SwarmStep(best.strategy.id, best.strategy.vuln_class, best.score, landed)
        )
        remaining = [s for s in remaining if s.id != best.strategy.id]  # attempted -> drop
    total_ms = (time.perf_counter() - t0) * 1000.0

    return SwarmReport(
        n_strategies=len(strategies),
        total_ms=total_ms,
        initial_ranking=initial,
        trajectory=trajectory,
        discovered=list(eng.live.discovered),
        signal=dict(eng.live.worked),
        unreached=[s.id for s in remaining],
    )
