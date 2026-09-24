"""Benchmark harness tests (offline echo backend)."""

import pytest

from offsec_one.agent import Finding, OffSecOne
from offsec_one.bench import BenchCase, run
from raze import Raze


def _cases():
    return [
        BenchCase(Finding(target="a.example.com", topic="web", title="c1"), exploitable_truth=True),
        BenchCase(Finding(target="b.example.com", topic="network", title="c2",
                          state={"open_ports": [6379]}), exploitable_truth=True),
        BenchCase(Finding(target="c.example.com", topic="crypto", title="c3"), exploitable_truth=False),
    ]


def _factory():
    return OffSecOne(raze=Raze())


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
