import pytest

from raze.calibration import expected_calibration_error


def test_perfect_calibration_is_zero():
    # 100% confident and always correct; 0% confident and always wrong.
    pairs = [(1.0, True)] * 50 + [(0.0, False)] * 50
    report = expected_calibration_error(pairs)
    assert report.ece == pytest.approx(0.0, abs=1e-9)
    assert report.n == 100


def test_overconfidence_produces_positive_ece():
    # Claims 0.9 confidence but only right half the time.
    pairs = [(0.9, i % 2 == 0) for i in range(100)]
    report = expected_calibration_error(pairs)
    assert report.ece == pytest.approx(0.4, abs=1e-6)  # |0.9 - 0.5|


def test_empty_raises():
    with pytest.raises(ValueError):
        expected_calibration_error([])


def test_out_of_range_raises():
    with pytest.raises(ValueError):
        expected_calibration_error([(1.5, True)])


def test_summary_flags_aggregate_only():
    report = expected_calibration_error([(0.5, True), (0.5, False)])
    assert "Aggregate only" in report.summary()
