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
from raze.judgments import (
    CombinedJudgment,
    Exploitability,
    Impact,
    Judgment,
    JudgmentContext,
    NextAction,
    Novelty,
    Reachability,
)
from raze.model import Backend, EchoBackend, Raze
from raze.topics import ALL_TOPICS, Signal, Topic, analyze
from raze.validators import ValidationResult, validate_finding

__all__ = [
    "ALL_TOPICS",
    "Assessment",
    "Backend",
    "CalibratedBackend",
    "CalibrationReport",
    "CombinedJudgment",
    "Decision",
    "EchoBackend",
    "Exploitability",
    "Finding",
    "Impact",
    "Judgment",
    "JudgmentContext",
    "LLMBackend",
    "NextAction",
    "Novelty",
    "Raze",
    "RazeAgent",
    "Reachability",
    "Scope",
    "ScopeError",
    "Signal",
    "TemperatureScaler",
    "Topic",
    "ValidationResult",
    "analyze",
    "build_decision",
    "expected_calibration_error",
    "fit_temperature",
    "validate_finding",
]
