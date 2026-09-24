"""Raze — an offensive-security agent built on a System One model (Jev family).

`Raze` (in `raze.model`) is the System One model: state -> typed judgment.
`RazeAgent` (in `raze.agent`) is the agent that orchestrates the model,
deterministic analyzers, and validators behind an authorization boundary.
"""

__version__ = "0.0.1"

from raze.agent import Assessment, Finding, RazeAgent
from raze.authz import Scope, ScopeError
from raze.backends import LLMBackend
from raze.calibration import CalibrationReport, expected_calibration_error
from raze.calibrator import CalibratedBackend, TemperatureScaler, fit_temperature
from raze.decide import Decision, build_decision
from raze.engagement import AttackChain, EngagementReport, run_engagement
from raze.judgments import (
    AssetPriority,
    CombinedJudgment,
    Exploitability,
    GoNoGo,
    Impact,
    InScope,
    Judgment,
    JudgmentContext,
    NextAction,
    Novelty,
    Reachability,
    TechniqueSelection,
)
from raze.killchain import (
    DECISION_REGISTRY,
    DecisionKind,
    Phase,
    human_gated_kinds,
)
from raze.model import Backend, EchoBackend, Raze
from raze.topics import ALL_TOPICS, Signal, Topic, analyze
from raze.validators import ValidationResult, validate_finding

__all__ = [
    "ALL_TOPICS",
    "DECISION_REGISTRY",
    "Assessment",
    "AssetPriority",
    "AttackChain",
    "Backend",
    "CalibratedBackend",
    "CalibrationReport",
    "CombinedJudgment",
    "Decision",
    "DecisionKind",
    "EchoBackend",
    "EngagementReport",
    "Exploitability",
    "Finding",
    "GoNoGo",
    "Impact",
    "InScope",
    "Judgment",
    "JudgmentContext",
    "LLMBackend",
    "NextAction",
    "Novelty",
    "Phase",
    "Raze",
    "RazeAgent",
    "Reachability",
    "Scope",
    "ScopeError",
    "Signal",
    "TechniqueSelection",
    "TemperatureScaler",
    "Topic",
    "ValidationResult",
    "analyze",
    "build_decision",
    "expected_calibration_error",
    "fit_temperature",
    "human_gated_kinds",
    "run_engagement",
    "validate_finding",
]
