"""Deterministic validators that gate Raze judgments.

A model probability is never the last word. These checks are explicit and
testable (see tests/test_validators.py). A finding a validator can disprove is
downgraded regardless of how confident Raze was.

Blocking conditions (exhaustive for this scaffold):
  1. No reproduction evidence for an "exploitable" verdict  -> block.
  2. Reachability judged false                              -> block.
  3. Novelty in {duplicate, theoretical}                    -> drop from queue.
  4. Probability below the topic floor                      -> hold for review.
"""

from __future__ import annotations

from dataclasses import dataclass

from raze.judgments import ExploitVerdict, NoveltyClass


@dataclass
class ValidationResult:
    accepted: bool
    disposition: str  # "queued" | "held" | "dropped" | "blocked"
    reasons: list[str]


def validate_finding(
    *,
    verdict: ExploitVerdict,
    probability: float,
    reachable: bool,
    novelty: NoveltyClass,
    has_reproduction: bool,
    probability_floor: float = 0.6,
) -> ValidationResult:
    reasons: list[str] = []

    if verdict == ExploitVerdict.exploitable and not has_reproduction:
        reasons.append("exploitable verdict without reproduction evidence")
        return ValidationResult(False, "blocked", reasons)

    if not reachable:
        reasons.append("target judged not reachable")
        return ValidationResult(False, "blocked", reasons)

    if novelty in (NoveltyClass.duplicate, NoveltyClass.theoretical):
        reasons.append(f"novelty={novelty.value}")
        return ValidationResult(False, "dropped", reasons)

    if probability < probability_floor:
        reasons.append(f"probability {probability:.2f} below floor {probability_floor:.2f}")
        return ValidationResult(False, "held", reasons)

    return ValidationResult(True, "queued", ["passed deterministic validation"])
