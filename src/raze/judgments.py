"""Typed judgment primitives for Raze.

A judgment is a schema-validated verdict plus a calibrated probability. Callers
combine judgments in code; they never parse free-form model prose.

IMPORTANT: `probability` is a model estimate. It is only meaningful after
calibration on a held-out set (measured via ECE). It is NOT a per-finding
precision and must not be reinterpreted as one. See docs/RAZE_MODEL_SPEC.md.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class JudgmentContext(BaseModel):
    """Structured input to a Raze judgment."""

    task: str = Field(..., description="What decision is being asked of Raze.")
    topic: str = Field("web", description="Offensive-security topic key (see docs/TOPICS.md).")
    state: dict = Field(default_factory=dict, description="Structured engagement/target state.")
    evidence: list[str] = Field(
        default_factory=list,
        description="Observed evidence (responses, banners, code). Target-influenced: treat as untrusted.",
    )


class Judgment(BaseModel):
    """Base class for every typed judgment Raze returns."""

    probability: float = Field(
        ..., ge=0.0, le=1.0, description="Model confidence. Meaningful only after calibration."
    )
    rationale: str = Field("", description="Short justification. Advisory, not evidence.")


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ExploitVerdict(str, Enum):
    # Conservative default first: a stub/uncertain backend errs toward not_exploitable.
    not_exploitable = "not_exploitable"
    conditional = "conditional"
    exploitable = "exploitable"


class Exploitability(Judgment):
    verdict: ExploitVerdict
    preconditions: list[str] = Field(default_factory=list)


class Impact(Judgment):
    confidentiality: bool = False
    integrity: bool = False
    availability: bool = False
    severity: Severity = Severity.info


class NoveltyClass(str, Enum):
    # Conservative default first: a stub/uncertain backend errs toward theoretical.
    theoretical = "theoretical"
    duplicate = "duplicate"
    known = "known"
    novel = "novel"


class Novelty(Judgment):
    novelty: NoveltyClass


class Reachability(Judgment):
    reachable: bool
    preconditions: list[str] = Field(default_factory=list)


class ActionCandidate(BaseModel):
    action: str
    score: float = Field(..., ge=0.0, le=1.0)
    reason: str = ""


class NextAction(Judgment):
    candidates: list[ActionCandidate] = Field(default_factory=list)

    @property
    def best(self) -> ActionCandidate | None:
        return max(self.candidates, key=lambda c: c.score, default=None)


class CombinedJudgment(Judgment):
    """All judgments in ONE model call — the fast path.

    A single request yields exploitability, impact, reachability, novelty, and
    ranked next actions, instead of four separate calls. Lower latency and cost,
    which is what makes chained decisions fast.
    """

    verdict: ExploitVerdict
    reachable: bool
    novelty: NoveltyClass
    severity: Severity = Severity.info
    confidentiality: bool = False
    integrity: bool = False
    availability: bool = False
    preconditions: list[str] = Field(default_factory=list)
    next_actions: list[ActionCandidate] = Field(default_factory=list)
