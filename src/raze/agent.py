"""Raze orchestration: propose -> validate -> queue.

The agent asks Raze for typed judgments about a candidate finding, then gates
those judgments with deterministic validators behind the authorization boundary.
It proposes a disposition; the human operator disposes.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from raze.authz import Scope
from raze.decide import Decision, build_decision
from raze.judgments import (
    CombinedJudgment,
    Exploitability,
    Impact,
    JudgmentContext,
    Novelty,
    Reachability,
)
from raze.model import Raze
from raze.topics import Signal, analyze
from raze.validators import ValidationResult, validate_finding


@dataclass
class Finding:
    """A candidate finding fed into Raze."""

    target: str
    topic: str
    title: str
    evidence: list[str] = field(default_factory=list)
    has_reproduction: bool = False
    state: dict = field(default_factory=dict)


@dataclass
class Assessment:
    finding: Finding
    signals: list[Signal]
    exploitability: Exploitability
    impact: Impact
    reachability: Reachability
    novelty: Novelty
    result: ValidationResult


class RazeAgent:
    def __init__(
        self, raze: Raze | None = None, scope: Scope | None = None, run_analyzers: bool = True
    ) -> None:
        self.raze = raze or Raze()
        self.scope = scope
        self.run_analyzers = run_analyzers

    def assess(self, finding: Finding) -> Assessment:
        # Hard authorization boundary first — before any analyzer or judgment.
        if self.scope is not None:
            self.scope.require(finding.target)

        # Deterministic detectors turn collected state into evidence signals.
        signals = analyze(finding.topic, finding.state) if self.run_analyzers else []
        evidence = list(finding.evidence) + [str(s) for s in signals]

        ctx = JudgmentContext(
            task=f"Assess finding: {finding.title}",
            topic=finding.topic,
            state=finding.state,
            evidence=evidence,
        )

        exploitability = self.raze.judge(Exploitability, ctx)
        impact = self.raze.judge(Impact, ctx)
        reachability = self.raze.judge(Reachability, ctx)
        novelty = self.raze.judge(Novelty, ctx)

        result = validate_finding(
            verdict=exploitability.verdict,
            probability=exploitability.probability,
            reachable=reachability.reachable,
            novelty=novelty.novelty,
            has_reproduction=finding.has_reproduction,
        )

        return Assessment(
            finding=finding,
            signals=signals,
            exploitability=exploitability,
            impact=impact,
            reachability=reachability,
            novelty=novelty,
            result=result,
        )

    def decide(self, finding: Finding) -> Decision:
        """Fast path: one combined model call, chained multi-factor decision.

        Produces a single ranked, actionable Decision instead of four separate
        judgments — lower latency, decisive output.
        """
        if self.scope is not None:
            self.scope.require(finding.target)

        signals = analyze(finding.topic, finding.state) if self.run_analyzers else []
        evidence = list(finding.evidence) + [str(s) for s in signals]
        ctx = JudgmentContext(
            task=f"Decide on finding: {finding.title}",
            topic=finding.topic,
            state=finding.state,
            evidence=evidence,
        )

        started = time.perf_counter()
        judgment = self.raze.judge(CombinedJudgment, ctx)  # single call
        latency_ms = (time.perf_counter() - started) * 1000.0

        result = validate_finding(
            verdict=judgment.verdict,
            probability=judgment.probability,
            reachable=judgment.reachable,
            novelty=judgment.novelty,
            has_reproduction=finding.has_reproduction,
        )
        return build_decision(
            finding_title=finding.title,
            judgment=judgment,
            signals=signals,
            validation=result,
            has_reproduction=finding.has_reproduction,
            latency_ms=latency_ms,
        )
