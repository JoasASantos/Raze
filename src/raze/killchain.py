"""The offensive-security decision surface.

Raze is a decision engine for the *whole* engagement, in the Jev/Laya line: at
every phase of the kill chain there is a typed decision to make. This module
enumerates those decisions, binds each to a judgment schema, records which phase
it belongs to, and — critically — which ones are state-changing/offensive and
therefore require explicit human approval before Raze's answer is acted on.

Raze answers the decision; it never autonomously executes a human-gated one.
See docs/DECISIONS.md for the full map of vulnerability classes and tasks.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from raze.judgments import (
    AssetPriority,
    CombinedJudgment,
    Exploitability,
    GoNoGo,
    Impact,
    InScope,
    Judgment,
    NextAction,
    Novelty,
    Reachability,
    TechniqueSelection,
)


class Phase(str, Enum):
    recon = "recon"
    enumeration = "enumeration"
    vuln_analysis = "vuln_analysis"
    exploitation = "exploitation"
    post_exploitation = "post_exploitation"
    lateral_movement = "lateral_movement"
    privilege_escalation = "privilege_escalation"
    impact = "impact"
    reporting = "reporting"


class DecisionKind(str, Enum):
    in_scope = "in_scope"
    asset_priority = "asset_priority"
    exploitability = "exploitability"
    impact = "impact"
    reachability = "reachability"
    novelty = "novelty"
    technique_selection = "technique_selection"
    go_no_go = "go_no_go"
    next_pivot = "next_pivot"
    privesc_path = "privesc_path"
    severity = "severity"
    report_inclusion = "report_inclusion"
    combined = "combined"


@dataclass(frozen=True)
class DecisionSpec:
    kind: DecisionKind
    phase: Phase
    schema: type[Judgment]
    requires_human: bool  # True = offensive/state-changing; Raze proposes, human acts
    question: str


DECISION_REGISTRY: dict[DecisionKind, DecisionSpec] = {
    DecisionKind.in_scope: DecisionSpec(
        DecisionKind.in_scope, Phase.recon, InScope, False,
        "Is this target in scope and worth engaging?"),
    DecisionKind.asset_priority: DecisionSpec(
        DecisionKind.asset_priority, Phase.enumeration, AssetPriority, False,
        "How much attention does this asset deserve?"),
    DecisionKind.exploitability: DecisionSpec(
        DecisionKind.exploitability, Phase.vuln_analysis, Exploitability, False,
        "Can this finding be exploited in this context?"),
    DecisionKind.impact: DecisionSpec(
        DecisionKind.impact, Phase.vuln_analysis, Impact, False,
        "What does exploitation grant (CIA + severity)?"),
    DecisionKind.reachability: DecisionSpec(
        DecisionKind.reachability, Phase.vuln_analysis, Reachability, False,
        "Is the vulnerable code/endpoint reachable?"),
    DecisionKind.novelty: DecisionSpec(
        DecisionKind.novelty, Phase.vuln_analysis, Novelty, False,
        "Is this novel, known, duplicate, or theoretical?"),
    DecisionKind.technique_selection: DecisionSpec(
        DecisionKind.technique_selection, Phase.exploitation, TechniqueSelection, True,
        "Which technique should be attempted for this weakness?"),
    DecisionKind.go_no_go: DecisionSpec(
        DecisionKind.go_no_go, Phase.exploitation, GoNoGo, True,
        "Is it safe/authorized to execute this action now?"),
    DecisionKind.next_pivot: DecisionSpec(
        DecisionKind.next_pivot, Phase.lateral_movement, NextAction, True,
        "Where to pivot next from this foothold?"),
    DecisionKind.privesc_path: DecisionSpec(
        DecisionKind.privesc_path, Phase.privilege_escalation, NextAction, True,
        "Which privilege-escalation path to take?"),
    DecisionKind.severity: DecisionSpec(
        DecisionKind.severity, Phase.reporting, Impact, False,
        "What severity should this finding be reported at?"),
    DecisionKind.report_inclusion: DecisionSpec(
        DecisionKind.report_inclusion, Phase.reporting, GoNoGo, False,
        "Should this finding be included in the report?"),
    DecisionKind.combined: DecisionSpec(
        DecisionKind.combined, Phase.vuln_analysis, CombinedJudgment, False,
        "One-call combined judgment for the fast decision path."),
}


def human_gated_kinds() -> list[DecisionKind]:
    """Decision kinds Raze must never act on without explicit human approval."""
    return [k for k, spec in DECISION_REGISTRY.items() if spec.requires_human]


def spec_for(kind: DecisionKind) -> DecisionSpec:
    return DECISION_REGISTRY[kind]
