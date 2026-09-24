"""CVSS v3.1 base-score calculator (deterministic, stdlib only).

Parse a base vector string and compute the base score + severity rating, and map
that to Raze's Severity enum so impact judgments and priority scoring can be
grounded in a standard rather than a guess.

    score = base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")  # 9.8
    rating = severity_rating(score)                                     # "critical"
"""

from __future__ import annotations

import math

from raze.judgments import Severity

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse_vector(vector: str) -> dict[str, str]:
    parts = [p for p in vector.strip().split("/") if p]
    metrics: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        if key == "CVSS":
            continue
        metrics[key] = value
    missing = [m for m in _REQUIRED if m not in metrics]
    if missing:
        raise ValueError(f"CVSS vector missing metrics: {missing}")
    return metrics


def _roundup(x: float) -> float:
    # Official CVSS v3.1 roundup.
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"
    pr_table = _PR_C if scope_changed else _PR_U
    try:
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        pr = pr_table[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError as exc:
        raise ValueError(f"CVSS vector has an invalid metric value: {exc}") from exc

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + exploitability) if scope_changed else (impact + exploitability)
    return _roundup(min(raw, 10.0))


def severity_rating(score: float) -> str:
    if score <= 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


_RATING_TO_SEVERITY = {
    "none": Severity.info,
    "low": Severity.low,
    "medium": Severity.medium,
    "high": Severity.high,
    "critical": Severity.critical,
}


def cvss_to_severity(vector_or_score: str | float) -> Severity:
    score = base_score(vector_or_score) if isinstance(vector_or_score, str) else vector_or_score
    return _RATING_TO_SEVERITY[severity_rating(score)]
