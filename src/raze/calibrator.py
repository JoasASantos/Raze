"""Probability calibration for Raze — the first "own" component on top of a
reused LLM.

A reused frontier model gives typed judgments, but its self-reported
`probability` is usually miscalibrated. Temperature scaling is a one-parameter
post-hoc fix: learn a single scalar T on a labeled set and rescale every
probability through the logit. Cheap, needs little data, and does not touch the
base model.

    scaler = fit_temperature(pairs)        # pairs: (probability, correct)
    calibrated_p = scaler.apply(raw_p)
    raze = Raze(backend=CalibratedBackend(inner_backend, scaler))

This does not invent calibration — measure it with raze.calibration before and
after (ECE), on a held-out set, and only keep the scaler if it helps.
"""

from __future__ import annotations

import math

from raze.judgments import Judgment, JudgmentContext
from raze.model import Backend

_EPS = 1e-6


def _sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


def _logit(p: float) -> float:
    p = min(max(p, _EPS), 1.0 - _EPS)
    return math.log(p / (1.0 - p))


def _nll(pairs: list[tuple[float, bool]], temperature: float) -> float:
    total = 0.0
    for p, correct in pairs:
        q = _sigmoid(_logit(p) / temperature)
        q = min(max(q, _EPS), 1.0 - _EPS)
        total -= math.log(q) if correct else math.log(1.0 - q)
    return total


def _minimize(f, lo: float, hi: float, iters: int = 100) -> float:
    """Golden-section search for the minimum of a unimodal 1-D function."""
    gr = (math.sqrt(5.0) - 1.0) / 2.0
    c = hi - gr * (hi - lo)
    d = lo + gr * (hi - lo)
    for _ in range(iters):
        if f(c) < f(d):
            hi = d
        else:
            lo = c
        c = hi - gr * (hi - lo)
        d = lo + gr * (hi - lo)
    return (lo + hi) / 2.0


class TemperatureScaler:
    """One-parameter calibrator. T>1 softens overconfidence; T<1 sharpens."""

    def __init__(self, temperature: float = 1.0) -> None:
        self.temperature = temperature
        self.fitted = False

    def apply(self, probability: float) -> float:
        return _sigmoid(_logit(probability) / self.temperature)

    def fit(
        self, pairs: list[tuple[float, bool]], *, t_min: float = 0.05, t_max: float = 20.0
    ) -> TemperatureScaler:
        if not pairs:
            raise ValueError("Need labeled (probability, correct) pairs to fit temperature.")
        self.temperature = _minimize(lambda t: _nll(pairs, t), t_min, t_max)
        self.fitted = True
        return self


def fit_temperature(pairs: list[tuple[float, bool]]) -> TemperatureScaler:
    return TemperatureScaler().fit(pairs)


class CalibratedBackend:
    """Wrap any Backend and rescale each judgment's probability with a scaler."""

    def __init__(self, backend: Backend, scaler: TemperatureScaler) -> None:
        self.backend = backend
        self.scaler = scaler

    def judge(self, schema: type[Judgment], context: JudgmentContext) -> Judgment:
        judgment = self.backend.judge(schema, context)
        return judgment.model_copy(update={"probability": self.scaler.apply(judgment.probability)})
