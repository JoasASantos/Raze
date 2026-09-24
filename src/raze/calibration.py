"""Calibration measurement for Raze probabilities.

Expected Calibration Error (ECE) over a fixed, labeled test set of
`(predicted_probability, correct)` pairs.

READ THIS: ECE is an AGGREGATE statistic. It is the average gap between predicted
confidence and observed accuracy across probability buckets. It is NOT a ± band on
any single prediction, and you cannot derive precision, recall, false-positive
counts, or analyst-hours from it. Those require measured predictions and labels on
the same test set. Any per-finding "0.8 ± ECE" interpretation is a category error.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Bucket:
    lo: float
    hi: float
    count: int
    avg_confidence: float
    accuracy: float


@dataclass
class CalibrationReport:
    ece: float
    n: int
    buckets: list[Bucket]

    def summary(self) -> str:
        return (
            f"ECE={self.ece:.4f} over n={self.n} predictions "
            f"({sum(1 for b in self.buckets if b.count)} non-empty buckets). "
            f"Aggregate only — not a per-finding band, not precision/recall."
        )


def expected_calibration_error(
    pairs: list[tuple[float, bool]], *, n_bins: int = 10
) -> CalibrationReport:
    """Compute ECE from (predicted_probability, correct) pairs.

    pairs: predicted probability in [0,1] and whether the prediction was correct.
    n_bins: number of equal-width confidence buckets.
    """
    if not pairs:
        raise ValueError("Need at least one (probability, correct) pair to compute ECE.")
    for p, _ in pairs:
        if not 0.0 <= p <= 1.0:
            raise ValueError(f"Probability out of range: {p}")

    n = len(pairs)
    buckets: list[Bucket] = []
    ece = 0.0
    for b in range(n_bins):
        lo = b / n_bins
        hi = (b + 1) / n_bins
        # Last bucket is closed on the right so p==1.0 lands somewhere.
        in_bin = [
            (p, c)
            for (p, c) in pairs
            if (lo <= p < hi) or (b == n_bins - 1 and p == 1.0)
        ]
        count = len(in_bin)
        if count:
            avg_conf = sum(p for p, _ in in_bin) / count
            acc = sum(1 for _, c in in_bin if c) / count
            ece += (count / n) * abs(avg_conf - acc)
        else:
            avg_conf = 0.0
            acc = 0.0
        buckets.append(Bucket(lo=lo, hi=hi, count=count, avg_confidence=avg_conf, accuracy=acc))

    return CalibrationReport(ece=ece, n=n, buckets=buckets)
