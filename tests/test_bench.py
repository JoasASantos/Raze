"""Benchmark harness tests (offline echo backend)."""

import pytest

from raze import Raze
from raze.agent import Finding, RazeAgent
from raze.bench import BenchCase, run


def _cases():
    return [
        BenchCase(Finding(target="a.example.com", topic="web", title="c1"), exploitable_truth=True),
        BenchCase(Finding(target="b.example.com", topic="network", title="c2",
                          state={"open_ports": [6379]}), exploitable_truth=True),
        BenchCase(Finding(target="c.example.com", topic="crypto", title="c3"), exploitable_truth=False),
    ]


def _factory():
    return RazeAgent(raze=Raze())


def test_report_has_metadata_and_ece():
    report = run(_cases(), _factory, runs=4)
    assert report.metadata["n_runs"] == 4
    assert report.metadata["n_cases"] == 3
    assert "raze_version" in report.metadata and "git_revision" in report.metadata
    assert 0.0 <= report.ece <= 1.0
    assert report.n_predictions == 12  # 4 runs x 3 cases


def test_requires_at_least_two_runs():
    with pytest.raises(ValueError):
        run(_cases(), _factory, runs=1)


def test_alternating_order_reverses_odd_runs():
    report = run(_cases(), _factory, runs=2, alternate=True)
    assert report.runs[0].order == list(reversed(report.runs[1].order))


def test_empty_dataset_raises():
    with pytest.raises(ValueError):
        run([], _factory, runs=3)


def test_to_dict_serializable():
    import json

    report = run(_cases(), _factory, runs=2)
    json.dumps(report.to_dict())  # must not raise


def test_calibration_fields_present_with_split():
    report = run(_cases(), _factory, runs=4, calibrate=True)
    assert report.ece_test_raw is not None
    assert report.ece_test_calibrated is not None
    assert report.temperature is not None


def test_calibration_skipped_when_disabled():
    report = run(_cases(), _factory, runs=2, calibrate=False)
    assert report.ece_test_raw is None
    assert report.temperature is None


def test_metrics_measured_and_bounded():
    report = run(_cases(), _factory, runs=3)
    m = report.metrics
    for key in ("accuracy", "precision", "recall", "f1"):
        assert 0.0 <= m[key] <= 1.0
    assert m["tp"] + m["fp"] + m["fn"] + m["tn"] == report.n_predictions


def test_per_difficulty_accuracy_when_meta_present():
    cases = [
        BenchCase(Finding(target="a.example.com", topic="web", title="c1"),
                  exploitable_truth=False, meta={"difficulty": "easy"}),
        BenchCase(Finding(target="b.example.com", topic="network", title="c2",
                          state={"open_ports": [6379]}),
                  exploitable_truth=True, meta={"difficulty": "hard"}),
    ]
    report = run(cases, _factory, runs=2)
    assert set(report.per_difficulty_accuracy) == {"easy", "hard"}
    # Echo backend predicts not_exploitable: correct on the negative (easy), wrong on positive (hard).
    assert report.per_difficulty_accuracy["easy"] == 1.0
    assert report.per_difficulty_accuracy["hard"] == 0.0
