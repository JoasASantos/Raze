"""OffSec One — offensive-security agent built on the Raze System One model."""

from offsec_one.agent import Assessment, Finding, OffSecOne
from offsec_one.authz import Scope, ScopeError
from offsec_one.topics import ANALYZERS, PROPOSED_TOPICS, Signal, analyze
from offsec_one.validators import ValidationResult, validate_finding

__all__ = [
    "OffSecOne",
    "Finding",
    "Assessment",
    "Scope",
    "ScopeError",
    "validate_finding",
    "ValidationResult",
    "analyze",
    "Signal",
    "ANALYZERS",
    "PROPOSED_TOPICS",
]

__version__ = "0.0.1"
