"""Turn results into ASCII text to paste into a ticket.

A pure function: results and time come in as arguments, so the same input always
gives the same text and the tests need no clock, network or operating system.
"""

from __future__ import annotations

from datetime import datetime, timezone

from layerwise import __version__
from layerwise.models import CheckResult, Status
from layerwise.registry import Context
from layerwise.targets import Target
from layerwise.text import to_ascii

TEAM_LOCAL = "desktop support (this PC or its LAN/Wi-Fi)"
TEAM_DNS = "DNS"
TEAM_FIREWALL = "firewall"
TEAM_SERVICE = "service owner"
TEAM_SITE = "site/certificate owner"
TEAM_APPLICATION = "application"
TEAM_LATENCY = "network (latency or path)"

LABELS = {Status.OK: " OK ", Status.WARN: "WARN", Status.FAIL: "FAIL", Status.SKIP: "SKIP"}


def suggested_team(result: CheckResult) -> str:
    """Who can fix what this result shows, from its check, its status and, for TCP, its reason."""
    if result.name == "LOCAL":
        return TEAM_LOCAL
    if result.name == "DNS":
        # A DNS warning is a slow answer: the resolver works, the path to it is slow.
        return TEAM_LATENCY if result.status is Status.WARN else TEAM_DNS
    if result.name.startswith("TCP"):
        reason = result.details.get("reason")
        if result.status is Status.WARN:
            if reason == "slow":
                return TEAM_LATENCY
            # Any other TCP warning is a failure downgraded because the other family works.
            return f"network ({result.name.split()[-1]})"
        # A reset means the host is there and nothing listens: the service, not the path.
        return TEAM_SERVICE if reason == "refused" else TEAM_FIREWALL
    if result.name == "TLS":
        return TEAM_SITE
    return TEAM_APPLICATION


def verdict(results: list[CheckResult]) -> str:
    """The first failing check decides; with no failure, the first warning."""
    for status in (Status.FAIL, Status.WARN):
        first = next((r for r in results if r.status is status), None)
        if first is not None:
            return (
                f"VERDICT: {status.name} at {first.name} -> suggested team: {suggested_team(first)}"
            )
    return "VERDICT: OK - no escalation needed"


def _evidence(value: object) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(to_ascii(str(item)) for item in value) or "none"
    return to_ascii(str(value))


def _target_block(
    target: Target, results: list[CheckResult], ctx: Context, now: datetime
) -> list[str]:
    local = next((r for r in results if r.name == "LOCAL"), None)
    lines = [
        verdict(results),
        "",
        f"Date:    {now.astimezone(timezone.utc):%Y-%m-%d %H:%M:%S} UTC",
        f"Tool:    layerwise {__version__}",
        f"Local:   {local.summary if local else 'not tested'}",
        f"Target:  {target}",
        f"Tried:   {', '.join(ctx.tried) if ctx.tried else 'no address tested'}",
        "",
        "Checks:",
    ]
    for result in results:
        timing = f"{result.duration_ms:.0f} ms" if result.duration_ms is not None else "-"
        lines.append(f"  [{LABELS[result.status]}] {result.name:<8} {timing:>8}  {result.summary}")
        if result.hint and result.status in (Status.WARN, Status.FAIL):
            lines.append(f"{'':16}hint: {result.hint}")
        for key, value in result.details.items():
            if value is not None:
                lines.append(f"{'':16}{key}: {_evidence(value)}")
    for check, root in ctx.skipped:
        lines.append(f"  [ -- ] {check.upper():<8} {'-':>8}  not tested: {root} failed")
    return lines


def build_report(runs: list[tuple[Target, list[CheckResult], Context]], now: datetime) -> str:
    """One block per target, separated by a line of dashes."""
    blocks = ["\n".join(_target_block(target, results, ctx, now)) for target, results, ctx in runs]
    return ("\n\n" + "-" * 72 + "\n\n").join(blocks)
