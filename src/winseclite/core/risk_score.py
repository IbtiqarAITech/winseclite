from __future__ import annotations
from winseclite.core.models import Severity


def clamp_score(score: int) -> int:
    return max(0, min(100, score))


def severity_from_score(score: int) -> Severity:
    score = clamp_score(score)
    if score >= 81:
        return Severity.CRITICAL
    if score >= 61:
        return Severity.HIGH
    if score >= 41:
        return Severity.MEDIUM
    if score >= 21:
        return Severity.LOW
    return Severity.INFO
