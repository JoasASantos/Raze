"""Adaptive attack-path scoring against LIVE engagement state.

The instinct a real pentester has and a brute-force agent lacks: notice which
approach is landing and pour effort into it. Raze scores candidate attack
strategies in a single fast, deterministic, typed pass (no LLM in the loop) —
and goes further than a static score:

- **Live-state aware.** A strategy whose prerequisites are not yet discovered is
  discounted; once discoveries satisfy them, it becomes runnable.
- **Signal accumulation / reinforcement.** When a strategy lands, its class gains
  "signal"; future strategies of that class score higher, so attention follows
  what actually works.
- **Chain-aware.** Strategies that advance a known attack chain get a boost.
- **Explainable.** Every score carries its factor breakdown.
- **Gated.** Offensive execution stays human-approved; this only *ranks*.

The score is the signal, and the signal drives the swarm.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from raze.vulnclasses import get as get_class

_UNMET_PREREQ_MULT = 0.25
_PREREQ_BONUS = 12.0
_SIGNAL_WEIGHT = 8.0
_FAIL_PENALTY = 22.0
_CHAIN_BONUS = 10.0


@dataclass
class Strategy:
    id: str
    finding_title: str
    description: str
    vuln_class: str | None = None
    prerequisites: list[str] = field(default_factory=list)  # facts needed in live state
    yields: list[str] = field(default_factory=list)  # facts produced on success
    advances_chain: bool = False


@dataclass
class LiveState:
    discovered: set[str] = field(default_factory=set)
    worked: Counter = field(default_factory=Counter)  # vuln_class -> successes
    failed: Counter = field(default_factory=Counter)  # strategy id -> failures

    def record_success(self, strategy: Strategy) -> None:
        if strategy.vuln_class:
            self.worked[strategy.vuln_class] += 1
        self.discovered.update(strategy.yields)

    def record_failure(self, strategy: Strategy) -> None:
        self.failed[strategy.id] += 1

    def prereqs_met(self, strategy: Strategy) -> bool:
        return all(p in self.discovered for p in strategy.prerequisites)


@dataclass
class ScoredStrategy:
    strategy: Strategy
    score: float
    runnable: bool
    factors: dict

    def to_dict(self) -> dict:
        return {
            "id": self.strategy.id,
            "finding_title": self.strategy.finding_title,
            "description": self.strategy.description,
            "vuln_class": self.strategy.vuln_class,
            "score": round(self.score, 2),
            "runnable": self.runnable,
            "factors": self.factors,
        }


class AdaptiveScorer:
    """Single fast deterministic pass: strategy + live state -> typed score."""

    def score(self, strategy: Strategy, live: LiveState) -> ScoredStrategy:
        cls = get_class(strategy.vuln_class) if strategy.vuln_class else None
        base = (cls.typical_score * 10.0) if cls else 50.0

        met = live.prereqs_met(strategy)
        if strategy.prerequisites:
            frac = sum(1 for p in strategy.prerequisites if p in live.discovered) / len(
                strategy.prerequisites
            )
        else:
            frac = 1.0
        runnable_mult = 1.0 if met else _UNMET_PREREQ_MULT
        prereq_bonus = _PREREQ_BONUS if (met and strategy.prerequisites) else 0.0

        signal = live.worked.get(strategy.vuln_class, 0) if strategy.vuln_class else 0
        signal_bonus = _SIGNAL_WEIGHT * signal
        fail_pen = _FAIL_PENALTY * live.failed.get(strategy.id, 0)
        chain_bonus = _CHAIN_BONUS if strategy.advances_chain else 0.0

        raw = base * runnable_mult + prereq_bonus + signal_bonus + chain_bonus - fail_pen
        score = max(0.0, min(100.0, raw))
        factors = {
            "base": round(base, 2),
            "runnable_mult": runnable_mult,
            "prereq_fraction": round(frac, 2),
            "prereq_bonus": prereq_bonus,
            "signal": signal,
            "signal_bonus": signal_bonus,
            "chain_bonus": chain_bonus,
            "fail_penalty": fail_pen,
        }
        return ScoredStrategy(strategy=strategy, score=score, runnable=met, factors=factors)

    def rank(self, strategies: list[Strategy], live: LiveState) -> list[ScoredStrategy]:
        scored = [self.score(s, live) for s in strategies]
        # Runnable first, then by score — attention follows what can land now.
        return sorted(scored, key=lambda s: (s.runnable, s.score), reverse=True)


class AdaptiveEngagement:
    """Drives the fast-pass loop: score -> pick best -> report result -> re-score.

    The caller (an exploration agent / operator) executes the picked strategy and
    reports success/failure; Raze updates live state + signal and the ranking
    shifts toward what is working.
    """

    def __init__(self, scorer: AdaptiveScorer | None = None, live: LiveState | None = None) -> None:
        self.scorer = scorer or AdaptiveScorer()
        self.live = live or LiveState()

    def rank(self, strategies: list[Strategy]) -> list[ScoredStrategy]:
        return self.scorer.rank(strategies, self.live)

    def next_best(self, strategies: list[Strategy]) -> ScoredStrategy | None:
        ranked = self.rank(strategies)
        return ranked[0] if ranked else None

    def report_result(self, strategy: Strategy, success: bool) -> None:
        if success:
            self.live.record_success(strategy)  # accumulate signal + discoveries
        else:
            self.live.record_failure(strategy)
