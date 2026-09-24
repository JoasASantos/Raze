"""OffSec One orchestration: propose -> validate -> queue.

The agent asks Raze for typed judgments about a candidate finding, then gates
those judgments with deterministic validators behind the authorization boundary.
It proposes a disposition; the human operator disposes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from raze.judgments import (
    Exploitability,
    Impact,
    JudgmentContext,
    Novelty,
    Reachability,
)
from raze.model import Raze

from offsec_one.authz import Scope
from offsec_one.validators import ValidationResult, validate_finding


@dataclass
class Finding:
    """A candidate finding fed into OffSec One."""

    target: str
    topic: str
    title: str
    evidence: list[str] = field(default_factory=list)
    has_reproduction: bool = False
    state: dict = field(default_factory=dict)


@dataclass
class Assessment:
    finding: Finding
    exploitability: Exploitability
    impact: Impact
    reachability: Reachability
    novelty: Novelty
    result: ValidationResult


class OffSecOne:
    def __init__(self, raze: Raze | None = None, scope: Scope | None = None) -> None:
        self.raze = raze or Raze()
        self.scope = scope

    def assess(self, finding: Finding) -> Assessment:
        # Hard authorization boundary first — before any judgment.
        if self.scope is not None:
            self.scope.require(finding.target)

        ctx = JudgmentContext(
            task=f"Assess finding: {finding.title}",
            topic=finding.topic,
            state=finding.state,
            evidence=finding.evidence,
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
            exploitability=exploitability,
            impact=impact,
            reachability=reachability,
            novelty=novelty,
            result=result,
        )
