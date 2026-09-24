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
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from raze import __version__ as raze_version
from raze.agent import Finding, RazeAgent
from raze.calibration import expected_calibration_error
from raze.judgments import ExploitVerdict


@dataclass
class BenchCase:
    finding: Finding
    exploitable_truth: bool  # ground-truth label for this finding


@dataclass
class Prediction:
    case_title: str
    verdict: str
    probability: float
    predicted_positive: bool
    correct: bool
    disposition: str


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
    note: str = (
        "Exploratory. ECE is aggregate (not a per-finding band, not precision/recall). "
        "Results are valid only for the code state in metadata."
    )

    def to_dict(self) -> dict:
        return {
            "metadata": self.metadata,
            "ece": self.ece,
            "n_predictions": self.n_predictions,
            "disposition_mean": self.disposition_mean,
            "disposition_stdev": self.disposition_stdev,
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


def run(
    cases: list[BenchCase],
    agent_factory: Callable[[], RazeAgent],
    *,
    runs: int = 5,
    alternate: bool = True,
    backend_name: str = "echo",
) -> BenchReport:
    if runs < 2:
        raise ValueError("A benchmark needs at least 2 runs (single runs are observations).")
    if not cases:
        raise ValueError("No cases to run.")

    run_results: list[RunResult] = []
    pairs: list[tuple[float, bool]] = []

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
                    correct=correct,
                    disposition=a.result.disposition,
                )
            )
            pairs.append((a.exploitability.probability, correct))
        run_results.append(RunResult(index=i, order=[c.finding.title for c in ordered], predictions=preds))

    calibration = expected_calibration_error(pairs)

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
    )
