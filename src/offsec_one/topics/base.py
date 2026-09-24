"""Topic-analyzer framework.

A topic analyzer is a deterministic detector: it reads structured state and emits
`Signal`s (facts, not opinions). The agent folds those signals into a finding's
evidence, then Raze turns evidence into a typed judgment, and deterministic
validators gate the judgment. Analyzers never call the model and never act on a
target — they only interpret data already collected under an authorized scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Signal:
    name: str
    detail: str
    severity: str = "info"

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"Unknown severity {self.severity!r}; expected one of {SEVERITIES}.")

    def __str__(self) -> str:
        return f"[{self.severity}] {self.name}: {self.detail}"


@runtime_checkable
class Analyzer(Protocol):
    topic: str

    def analyze(self, state: dict) -> list[Signal]:
        """Return signals derived from `state`. Return [] when required inputs are absent."""
        ...
