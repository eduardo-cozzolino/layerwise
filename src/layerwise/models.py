"""Data types shared by checks, runner and report."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    SKIP = "skip"
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


# From least to most severe: used to compute the overall result of a target.
SEVERITY = [Status.SKIP, Status.OK, Status.WARN, Status.FAIL]


@dataclass
class CheckResult:
    name: str
    status: Status
    summary: str
    hint: str | None = None
    duration_ms: float | None = None
    details: dict = field(default_factory=dict)


def worst_status(results: list[CheckResult]) -> Status:
    if not results:
        return Status.SKIP
    return max((r.status for r in results), key=SEVERITY.index)
