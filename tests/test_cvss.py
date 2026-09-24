"""CVSS v3.1 base-score tests against known vectors."""

import pytest

from raze.cvss import base_score, cvss_to_severity, parse_vector, severity_rating
from raze.judgments import Severity

CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
MEDIUM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
SCOPE_CHANGED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
NONE = "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"


def test_critical_vector():
    assert base_score(CRITICAL) == 9.8
    assert severity_rating(9.8) == "critical"


def test_medium_vector():
    assert base_score(MEDIUM) == 5.3
    assert severity_rating(5.3) == "medium"


def test_scope_changed_vector():
    # Known reference score for this vector is 9.6.
    assert base_score(SCOPE_CHANGED) == 9.6


def test_no_impact_is_zero():
    assert base_score(NONE) == 0.0
    assert severity_rating(0.0) == "none"


def test_cvss_to_severity_enum():
    assert cvss_to_severity(CRITICAL) == Severity.critical
    assert cvss_to_severity(MEDIUM) == Severity.medium
    assert cvss_to_severity(0.0) == Severity.info


def test_missing_metric_raises():
    with pytest.raises(ValueError):
        parse_vector("CVSS:3.1/AV:N/AC:L")


def test_invalid_value_raises():
    with pytest.raises(ValueError):
        base_score("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
