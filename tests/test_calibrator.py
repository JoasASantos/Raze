"""Temperature-scaling calibrator tests."""

import pytest

from raze.calibration import expected_calibration_error
from raze.calibrator import CalibratedBackend, TemperatureScaler, fit_temperature
from raze.judgments import Exploitability, ExploitVerdict, JudgmentContext
from raze.model import Raze


def _overconfident_pairs(n=200):
    # Claims 0.95 confidence but is right only ~50% of the time.
    return [(0.95, i % 2 == 0) for i in range(n)]


def test_fit_softens_overconfidence():
    scaler = fit_temperature(_overconfident_pairs())
    assert scaler.fitted
    assert scaler.temperature > 1.0  # softening
    # A 0.95 claim should be pulled toward the ~0.5 empirical accuracy.
    assert scaler.apply(0.95) < 0.95
    assert scaler.apply(0.95) == pytest.approx(0.5, abs=0.1)


def test_calibration_improves_after_scaling():
    pairs = _overconfident_pairs()
    before = expected_calibration_error(pairs).ece
    scaler = fit_temperature(pairs)
    after = expected_calibration_error([(scaler.apply(p), c) for p, c in pairs]).ece
    assert after < before


def test_half_probability_is_fixed_point():
    scaler = TemperatureScaler(temperature=3.7)
    assert scaler.apply(0.5) == pytest.approx(0.5, abs=1e-9)


def test_empty_fit_raises():
    with pytest.raises(ValueError):
        fit_temperature([])


class _FixedBackend:
    def judge(self, schema, context):
        return schema(probability=0.95, rationale="x", verdict=ExploitVerdict.exploitable)


def test_calibrated_backend_rescales_probability():
    scaler = fit_temperature(_overconfident_pairs())
    raze = Raze(backend=CalibratedBackend(_FixedBackend(), scaler))
    j = raze.judge(Exploitability, JudgmentContext(task="t", topic="web"))
    assert j.verdict == ExploitVerdict.exploitable  # verdict untouched
    assert j.probability < 0.95  # probability calibrated
