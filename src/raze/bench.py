"""Benchmark harness for Raze.

Runs a labeled dataset through the agent multiple times with alternating case
order, records the harness version and code state per run, and reports aggregate
ECE plus across-run variance.

Honest-reporting contract (see benchmarks/README.md):
- A single run is an observation, not a demonstration. This harness always runs
  N>=2 and reports variance so a claim is never built on one execution.
- Every report records raze version + git revision + parameters, so runs made
  under different code states are never silently compared.
- ECE is aggregate. It is not a per-finding band and is not precision/recall.
"""

from __future__ import annotations

import statistics
import subprocess
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from raze import __version__ as raze_version
from raze.agent import Finding, RazeAgent
from raze.calibration import expected_calibration_error
from raze.calibrator import fit_temperature
from raze.judgments import ExploitVerdict


@dataclass
class BenchCase:
    finding: Finding
    exploitable_truth: bool  # ground-truth label for this finding
    meta: dict = field(default_factory=dict)  # cwe, difficulty, label_rationale, ...


@dataclass
class Prediction:
    case_title: str
    verdict: str
    probability: float
    predicted_positive: bool
    truth: bool
    correct: bool
    disposition: str
    difficulty: str | None = None


@dataclass
class RunResult:
    index: int
    order: list[str]
    predictions: list[Prediction]

    def disposition_counts(self) -> dict[str, int]:
        return dict(Counter(p.disposition for p in self.predictions))


@dataclass
class BenchReport:
    metadata: dict
    runs: list[RunResult]
    ece: float
    n_predictions: int
    disposition_mean: dict[str, float]
    disposition_stdev: dict[str, float]
    # Calibration on a held-out split (None when there are too few cases to split).
    ece_test_raw: float | None = None
    ece_test_calibrated: float | None = None
    temperature: float | None = None
    # Measured classification metrics (from predicted_positive vs. ground truth).
    metrics: dict = field(default_factory=dict)
    per_difficulty_accuracy: dict = field(default_factory=dict)
    note: str = (
        "Exploratory. ECE is aggregate (not a per-finding band, not precision/recall). "
        "Calibration is fit on the train split and reported on the disjoint test "
        "split. Results are valid only for the code state in metadata."
    )

    def to_dict(self) -> dict:
        return {
            "metadata": self.metadata,
            "ece": self.ece,
            "n_predictions": self.n_predictions,
            "disposition_mean": self.disposition_mean,
            "disposition_stdev": self.disposition_stdev,
            "ece_test_raw": self.ece_test_raw,
            "ece_test_calibrated": self.ece_test_calibrated,
            "temperature": self.temperature,
            "metrics": self.metrics,
            "per_difficulty_accuracy": self.per_difficulty_accuracy,
            "note": self.note,
            "runs": [
                {
                    "index": r.index,
                    "order": r.order,
                    "disposition_counts": r.disposition_counts(),
                    "predictions": [asdict(p) for p in r.predictions],
                }
                for r in self.runs
            ],
        }


def _git_revision() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL, text=True
        ).strip()
    except Exception:  # noqa: BLE001 - not a git repo / git absent
        return "unknown"


def _ordered(cases: list[BenchCase], run_index: int, alternate: bool) -> list[BenchCase]:
    if alternate and run_index % 2 == 1:
        return list(reversed(cases))
    return list(cases)


def _classification_metrics(preds: list[Prediction]) -> dict:
    """Measured accuracy/precision/recall/F1 from predicted_positive vs. truth.

    These are measured on the labeled set (allowed), and are NOT derived from ECE.
    """
    tp = sum(1 for p in preds if p.predicted_positive and p.truth)
    fp = sum(1 for p in preds if p.predicted_positive and not p.truth)
    fn = sum(1 for p in preds if not p.predicted_positive and p.truth)
    tn = sum(1 for p in preds if not p.predicted_positive and not p.truth)
    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1,
    }


def _per_difficulty_accuracy(preds: list[Prediction]) -> dict:
    out: dict[str, float] = {}
    seen = {p.difficulty for p in preds if p.difficulty}
    for d in sorted(seen):
        group = [p for p in preds if p.difficulty == d]
        out[d] = sum(1 for p in group if p.correct) / len(group)
    return out


def run(
    cases: list[BenchCase],
    agent_factory: Callable[[], RazeAgent],
    *,
    runs: int = 5,
    alternate: bool = True,
    backend_name: str = "echo",
    calibrate: bool = True,
    train_fraction: float = 0.5,
) -> BenchReport:
    if runs < 2:
        raise ValueError("A benchmark needs at least 2 runs (single runs are observations).")
    if not cases:
        raise ValueError("No cases to run.")

    # Split cases (not runs) into disjoint train/test so calibration is honest.
    n_train = int(len(cases) * train_fraction)
    train_titles = {c.finding.title for c in cases[:n_train]}

    run_results: list[RunResult] = []
    pairs: list[tuple[float, bool]] = []
    train_pairs: list[tuple[float, bool]] = []
    test_pairs: list[tuple[float, bool]] = []

    for i in range(runs):
        agent = agent_factory()  # fresh agent per run
        ordered = _ordered(cases, i, alternate)
        preds: list[Prediction] = []
        for case in ordered:
            a = agent.assess(case.finding)
            positive = a.exploitability.verdict == ExploitVerdict.exploitable
            correct = positive == case.exploitable_truth
            preds.append(
                Prediction(
                    case_title=case.finding.title,
                    verdict=a.exploitability.verdict.value,
                    probability=a.exploitability.probability,
                    predicted_positive=positive,
                    truth=case.exploitable_truth,
                    correct=correct,
                    disposition=a.result.disposition,
                    difficulty=case.meta.get("difficulty"),
                )
            )
            pair = (a.exploitability.probability, correct)
            pairs.append(pair)
            (train_pairs if case.finding.title in train_titles else test_pairs).append(pair)
        run_results.append(RunResult(index=i, order=[c.finding.title for c in ordered], predictions=preds))

    calibration = expected_calibration_error(pairs)
    all_preds = [p for r in run_results for p in r.predictions]
    metrics = _classification_metrics(all_preds)
    per_difficulty_accuracy = _per_difficulty_accuracy(all_preds)

    ece_test_raw = ece_test_calibrated = temperature = None
    if calibrate and train_pairs and test_pairs:
        ece_test_raw = expected_calibration_error(test_pairs).ece
        scaler = fit_temperature(train_pairs)
        temperature = scaler.temperature
        ece_test_calibrated = expected_calibration_error(
            [(scaler.apply(p), c) for p, c in test_pairs]
        ).ece

    all_dispositions = {d for r in run_results for d in r.disposition_counts()}
    disposition_mean: dict[str, float] = {}
    disposition_stdev: dict[str, float] = {}
    for d in sorted(all_dispositions):
        series = [r.disposition_counts().get(d, 0) for r in run_results]
        disposition_mean[d] = statistics.mean(series)
        disposition_stdev[d] = statistics.pstdev(series)

    metadata = {
        "raze_version": raze_version,
        "git_revision": _git_revision(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "n_cases": len(cases),
        "n_runs": runs,
        "alternate_order": alternate,
        "backend": backend_name,
    }

    return BenchReport(
        metadata=metadata,
        runs=run_results,
        ece=calibration.ece,
        n_predictions=calibration.n,
        disposition_mean=disposition_mean,
        disposition_stdev=disposition_stdev,
        ece_test_raw=ece_test_raw,
        ece_test_calibrated=ece_test_calibrated,
        temperature=temperature,
        metrics=metrics,
        per_difficulty_accuracy=per_difficulty_accuracy,
    )
