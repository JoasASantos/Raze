"""Engagement orchestration — campaign-level, not one finding at a time.

Ingests many findings, decides each on the fast path, correlates them into attack
chains, and produces one globally-ranked action plan with throughput timing.
This is the Laya-level layer: decisive across a whole engagement, fast, chained.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field

from raze.agent import Finding, RazeAgent
from raze.chaining import AttackChain, detect_class_chains
from raze.decide import Decision

_ACTIONABLE = ("exploit-now", "queue")
_CHAIN_BONUS_PER_STEP = 5.0
_CHAIN_BONUS_CAP = 20.0


@dataclass
class EngagementReport:
    decisions: list[Decision]  # globally ranked, priority desc
    chains: list[AttackChain]
    total_ms: float
    throughput: float  # findings per second
    n_findings: int
    action_counts: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "n_findings": self.n_findings,
            "total_ms": round(self.total_ms, 2),
            "throughput_per_s": round(self.throughput, 2),
            "action_counts": self.action_counts,
            "chains": [c.to_dict() for c in self.chains],
            "decisions": [d.to_dict() for d in self.decisions],
        }

    def top(self, n: int = 10) -> list[Decision]:
        return self.decisions[:n]


def _correlate(findings: list[Finding], decisions: list[Decision]) -> list[AttackChain]:
    """Compound priority when a single target has multiple actionable findings."""
    by_target: dict[str, list[Decision]] = defaultdict(list)
    for finding, decision in zip(findings, decisions):
        by_target[finding.target].append(decision)

    chains: list[AttackChain] = []
    for target, ds in by_target.items():
        actionable = [d for d in ds if d.action in _ACTIONABLE]
        if len(actionable) >= 2:
            bonus = min(_CHAIN_BONUS_PER_STEP * (len(actionable) - 1), _CHAIN_BONUS_CAP)
            for d in actionable:
                d.priority = min(100.0, d.priority + bonus)
            ordered = sorted(actionable, key=lambda d: d.priority, reverse=True)
            chains.append(
                AttackChain(
                    label=target,
                    steps=[d.finding_title for d in ordered],
                    chain_priority=ordered[0].priority,
                    why="multiple actionable findings on one target compound the attack path",
                    kind="target",
                )
            )
    return sorted(chains, key=lambda c: c.chain_priority, reverse=True)


def run_engagement(findings: list[Finding], agent: RazeAgent) -> EngagementReport:
    if not findings:
        raise ValueError("No findings in the engagement.")

    started = time.perf_counter()
    decisions = [agent.decide(f) for f in findings]
    elapsed = time.perf_counter() - started

    # Target-compounding chains, then rule-based cross-class attack paths.
    chains = _correlate(findings, decisions)
    chains = chains + detect_class_chains(decisions)  # both may boost priorities
    chains = sorted(chains, key=lambda c: c.chain_priority, reverse=True)
    ranked = sorted(decisions, key=lambda d: d.priority, reverse=True)

    action_counts: dict[str, int] = defaultdict(int)
    for d in ranked:
        action_counts[d.action] += 1

    total_ms = elapsed * 1000.0
    throughput = len(findings) / elapsed if elapsed > 0 else float("inf")

    return EngagementReport(
        decisions=ranked,
        chains=chains,
        total_ms=total_ms,
        throughput=throughput,
        n_findings=len(findings),
        action_counts=dict(action_counts),
    )
