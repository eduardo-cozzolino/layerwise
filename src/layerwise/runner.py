"""Run the checks in order, layer by layer, stopping when a lower layer fails.

There is no point testing TLS if TCP never connected, or HTTP if TLS failed:
the first failing layer is the answer.
"""

from __future__ import annotations

from layerwise.models import CheckResult, Status, worst_status
from layerwise.registry import REGISTRY, CheckSpec, Context
from layerwise.targets import Target


def run_registry(specs: list[CheckSpec], ctx: Context) -> list[CheckResult]:
    """Run specs by layer; skip one whose dependency failed.

    A disabled check is transparent: whoever depends on it inherits the outcome
    of the check it depends on (HTTP on port 80 runs if TCP passed, with TLS off).
    A skipped check is recorded in ctx.skipped with the check that really failed
    (HTTP after a TCP failure: "tcp", not "tls").
    """
    results: list[CheckResult] = []
    passed: dict[str, bool] = {}
    cause: dict[str, str] = {}  # check that did not pass -> the check that actually failed
    for spec in sorted(specs, key=lambda s: s.layer):
        dependency = spec.depends_on
        dependency_ok = dependency is None or passed[dependency]
        if not spec.enabled(ctx):
            passed[spec.name] = dependency_ok
            if not dependency_ok:
                cause[spec.name] = cause[dependency]
            continue
        if not dependency_ok:
            passed[spec.name] = False
            cause[spec.name] = cause[dependency]
            ctx.skipped.append((spec.name, cause[dependency]))
            continue
        spec_results = spec.run(ctx)
        results.extend(spec_results)
        passed[spec.name] = bool(spec_results) and worst_status(spec_results) is not Status.FAIL
        if not passed[spec.name]:
            cause[spec.name] = spec.name
    return results


def run_target(
    target: Target,
    timeout: float = 3.0,
    tls: bool | None = None,
    http: bool | None = None,
) -> tuple[list[CheckResult], Context]:
    """The results plus the context: addresses tried and checks skipped, for the report."""
    if tls is None:
        tls = target.scheme == "https" or (target.scheme is None and target.port == 443)
    if http is None:
        http = target.scheme is not None or target.port in (80, 443)

    ctx = Context(target=target, timeout=timeout, tls=tls, http=http)
    return run_registry(REGISTRY, ctx), ctx


def run_checks(
    target: Target,
    timeout: float = 3.0,
    tls: bool | None = None,
    http: bool | None = None,
) -> list[CheckResult]:
    """tls and http: None means "decide from scheme and port", True/False forces the choice."""
    return run_target(target, timeout, tls, http)[0]
