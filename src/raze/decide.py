"""Decision engine — fast, chained, decisive, multi-factor.

Turns a single CombinedJudgment (one model call) plus deterministic signals and
the validator result into one ranked, actionable Decision. The scoring is
deterministic and explainable: every Decision carries the factor breakdown.

Chaining / short-circuit:
  not reachable            -> drop (nothing downstream matters)
  validator blocks/drops   -> that disposition wins over any score
  otherwise                -> priority score picks the action
"""

from __future__ import annotations

from dataclasses import dataclass, field

from raze.judgments import CombinedJudgment, ExploitVerdict, NoveltyClass, Severity
from raze.topics.base import Signal
from raze.validators import ValidationResult
from raze.vulnclasses import VulnClass

_SEVERITY_ORDER = [Severity.info, Severity.low, Severity.medium, Severity.high, Severity.critical]

_SEVERITY_BASE = {
    Severity.info: 0.0,
    Severity.low: 20.0,
    Severity.medium: 50.0,
    Severity.high: 75.0,
    Severity.critical: 95.0,
}
_EXPLOIT_MULT = {
    ExploitVerdict.exploitable: 1.0,
    ExploitVerdict.conditional: 0.6,
    ExploitVerdict.not_exploitable: 0.1,
}
_NOVELTY_MULT = {
    NoveltyClass.novel: 1.0,
    NoveltyClass.known: 0.7,
    NoveltyClass.duplicate: 0.3,
    NoveltyClass.theoretical: 0.3,
}
_SIGNAL_POINTS = {"info": 0.0, "low": 3.0, "medium": 6.0, "high": 9.0, "critical": 12.0}


@dataclass
class Decision:
    finding_title: str
    action: str  # exploit-now | queue | investigate | hold | drop | blocked
    priority: float  # 0..100, ranked
    confidence: float  # model probability for the combined judgment
    factors: dict
    signals: list[str]
    rationale: str
    latency_ms: float | None = None
    validation_disposition: str = ""
    next_actions: list[str] = field(default_factory=list)
    # Adapted per vulnerability class (grounded in CWE + CVSS).
    vuln_class: str | None = None
    cwe: list[str] = field(default_factory=list)
    cvss_vector: str | None = None
    cvss_score: float | None = None
    severity: str = "info"

    def to_dict(self) -> dict:
        return {
            "finding_title": self.finding_title,
            "action": self.action,
            "priority": round(self.priority, 2),
            "confidence": self.confidence,
            "severity": self.severity,
            "vuln_class": self.vuln_class,
            "cwe": self.cwe,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "factors": self.factors,
            "signals": self.signals,
            "rationale": self.rationale,
            "latency_ms": self.latency_ms,
            "validation_disposition": self.validation_disposition,
            "next_actions": self.next_actions,
        }


def _priority(
    judgment: CombinedJudgment, severity: Severity, signals: list[Signal], has_reproduction: bool
) -> tuple[float, dict]:
    base = _SEVERITY_BASE[severity]
    exploit_mult = _EXPLOIT_MULT[judgment.verdict]
    novelty_mult = _NOVELTY_MULT[judgment.novelty]
    reach_mult = 1.0 if judgment.reachable else 0.2
    signal_boost = max((_SIGNAL_POINTS.get(s.severity, 0.0) for s in signals), default=0.0)
    repro_boost = 10.0 if has_reproduction else 0.0

    score = base * exploit_mult * novelty_mult * reach_mult + signal_boost + repro_boost
    score = max(0.0, min(100.0, score))
    factors = {
        "severity_base": base,
        "exploit_mult": exploit_mult,
        "novelty_mult": novelty_mult,
        "reach_mult": reach_mult,
        "signal_boost": signal_boost,
        "repro_boost": repro_boost,
    }
    return score, factors


def build_decision(
    *,
    finding_title: str,
    judgment: CombinedJudgment,
    signals: list[Signal],
    validation: ValidationResult,
    has_reproduction: bool,
    vuln_class: VulnClass | None = None,
    latency_ms: float | None = None,
) -> Decision:
    # Adapt severity per vulnerability class: take the higher of the model's
    # severity and the class's typical CVSS severity (never silently downgrade).
    severity = judgment.severity
    cwe: list[str] = []
    cvss_vector = cvss_score = None
    if vuln_class is not None:
        cwe = list(vuln_class.cwe)
        cvss_vector = vuln_class.typical_cvss
        cvss_score = vuln_class.typical_score
        if _SEVERITY_ORDER.index(vuln_class.typical_severity) > _SEVERITY_ORDER.index(severity):
            severity = vuln_class.typical_severity

    priority, factors = _priority(judgment, severity, signals, has_reproduction)
    next_actions = [c.action for c in judgment.next_actions]

    # Chaining: validator disposition wins; else score decides the action.
    if validation.disposition == "blocked":
        action, why = "blocked", "; ".join(validation.reasons)
    elif validation.disposition == "dropped":
        action, why = "drop", "; ".join(validation.reasons)
    elif validation.disposition == "held":
        action, why = "hold", "; ".join(validation.reasons)
    elif judgment.verdict == ExploitVerdict.exploitable and priority >= 75.0:
        action, why = "exploit-now", "high-priority exploitable finding (operator confirms)"
    elif priority >= 50.0:
        action, why = "queue", "actionable finding for the operator queue"
    else:
        action, why = "investigate", "needs more evidence before action"

    class_txt = f" class={vuln_class.id}" if vuln_class else ""
    rationale = (
        f"{action}: {why}. verdict={judgment.verdict.value} severity={severity.value}{class_txt} "
        f"reachable={judgment.reachable} novelty={judgment.novelty.value} priority={priority:.1f}"
    )
    return Decision(
        finding_title=finding_title,
        action=action,
        priority=priority,
        confidence=judgment.probability,
        factors=factors,
        signals=[str(s) for s in signals],
        rationale=rationale,
        latency_ms=latency_ms,
        validation_disposition=validation.disposition,
        next_actions=next_actions,
        vuln_class=vuln_class.id if vuln_class else None,
        cwe=cwe,
        cvss_vector=cvss_vector,
        cvss_score=cvss_score,
        severity=severity.value,
    )
