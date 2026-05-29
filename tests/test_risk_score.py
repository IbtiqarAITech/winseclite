from winseclite.core.models import Severity
from winseclite.core.risk_score import clamp_score, severity_from_score


def test_clamp_score() -> None:
    assert clamp_score(-1) == 0
    assert clamp_score(101) == 100


def test_severity_from_score() -> None:
    assert severity_from_score(10) == Severity.INFO
    assert severity_from_score(35) == Severity.LOW
    assert severity_from_score(55) == Severity.MEDIUM
    assert severity_from_score(70) == Severity.HIGH
    assert severity_from_score(90) == Severity.CRITICAL
