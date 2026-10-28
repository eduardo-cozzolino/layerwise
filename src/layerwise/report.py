"""Render results as human-readable text or as JSON."""

from __future__ import annotations

import json
import os
import textwrap
from typing import TextIO

from layerwise.models import CheckResult, Status, worst_status
from layerwise.registry import Context
from layerwise.targets import Target

LABELS = {Status.OK: " OK ", Status.WARN: "WARN", Status.FAIL: "FAIL", Status.SKIP: "SKIP"}
COLORS = {
    Status.OK: "\033[32m",
    Status.WARN: "\033[33m",
    Status.FAIL: "\033[31m",
    Status.SKIP: "\033[90m",
}
RESET = "\033[0m"


def use_color(stream: TextIO) -> bool:
    return stream.isatty() and "NO_COLOR" not in os.environ


def format_text(target: Target, results: list[CheckResult], color: bool = False) -> str:
    lines = [str(target)]
    for result in results:
        label = LABELS[result.status]
        if color:
            label = f"{COLORS[result.status]}{label}{RESET}"
        timing = f" ({result.duration_ms:.0f} ms)" if result.duration_ms is not None else ""
        lines.append(f"  [{label}] {result.name:<8} {result.summary}{timing}")
        if result.hint and result.status in (Status.WARN, Status.FAIL):
            lines.append(
                textwrap.fill(
                    result.hint,
                    width=90,
                    initial_indent=" " * 9 + "hint: ",
                    subsequent_indent=" " * 15,
                    # Wrap on spaces only: a hyphen inside a host (xn--...) or a command
                    # must not be split, or the suggested command cannot be copied.
                    break_on_hyphens=False,
                )
            )
    return "\n".join(lines)


def to_dict(target: Target, results: list[CheckResult], ctx: Context) -> dict:
    """One target; tried and skipped carry the same evidence as the --report text."""
    return {
        "target": str(target),
        "host": target.host,
        "port": target.port,
        "status": worst_status(results).value,
        "tried": ctx.tried,
        "skipped": [{"check": check, "cause": cause} for check, cause in ctx.skipped],
        "checks": [
            {
                "name": r.name,
                "status": r.status.value,
                "summary": r.summary,
                "hint": r.hint,
                "duration_ms": r.duration_ms,
                "details": r.details,
            }
            for r in results
        ],
    }


def format_json(runs: list[tuple[Target, list[CheckResult], Context]]) -> str:
    return json.dumps([to_dict(target, results, ctx) for target, results, ctx in runs], indent=2)
