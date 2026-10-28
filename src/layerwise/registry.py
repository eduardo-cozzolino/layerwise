"""The checks layerwise runs, in one table: name, layer and the check each one depends on.

The runner reads this table instead of hard-coding the order, so adding a check
means adding a row here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import IntEnum

from layerwise import checks, local
from layerwise.models import CheckResult, Status
from layerwise.targets import Target


class Layer(IntEnum):
    """Order of the diagnosis, from the machine itself up to the application.

    Not the OSI numbers: DNS is an application protocol in OSI, but nothing else
    can be tested before the name is resolved.
    """

    LOCAL = 0  # the machine itself: address, route out, gateway
    RESOLUTION = 1  # DNS
    TRANSPORT = 2  # TCP
    PATH = 3  # MTU along the path (no check yet)
    SECURITY = 4  # TLS
    APPLICATION = 5  # HTTP


@dataclass
class Context:
    """What the checks share: the request, plus what earlier layers found out."""

    target: Target
    timeout: float
    tls: bool
    http: bool
    addresses: list[tuple[int, str]] = field(default_factory=list)  # filled by DNS
    tried: list[str] = field(default_factory=list)  # filled by TCP: the addresses it tested
    connected: list[str] = field(default_factory=list)  # filled by TCP
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (check, failed root cause)


def _always(ctx: Context) -> bool:
    return True


@dataclass(frozen=True)
class CheckSpec:
    name: str
    layer: Layer
    depends_on: str | None
    run: Callable[[Context], list[CheckResult]]
    enabled: Callable[[Context], bool] = _always


# The checks are looked up on the module at call time (checks.check_dns, not a
# reference taken at import), so tests can replace them with monkeypatch.


def _run_local(ctx: Context) -> list[CheckResult]:
    return [local.check_local(ctx.target.host)]


def _run_dns(ctx: Context) -> list[CheckResult]:
    result, ctx.addresses = checks.check_dns(ctx.target.host)
    return [result]


def _run_tcp(ctx: Context) -> list[CheckResult]:
    # Test the first address of each family, so a broken IPv6 path does not hide behind IPv4.
    first_by_family: dict[int, str] = {}
    for family, address in ctx.addresses:
        first_by_family.setdefault(family, address)
    ctx.tried = list(first_by_family.values())

    tcp_results = [
        (address, checks.check_tcp(address, family, ctx.target.port, ctx.timeout))
        for family, address in first_by_family.items()
    ]
    ctx.connected = [address for address, result in tcp_results if result.status is not Status.FAIL]

    results = []
    for _, result in tcp_results:
        if ctx.connected and result.status is Status.FAIL:
            # One family works: the service is reachable, this path is degraded, not down.
            result = replace(
                result,
                status=Status.WARN,
                hint=(
                    f"{result.hint or ''} The other address family works, so most applications "
                    "will fall back to it, possibly after a delay."
                ).strip(),
            )
        results.append(result)
    return results


def _run_tls(ctx: Context) -> list[CheckResult]:
    return [checks.check_tls(ctx.target.host, ctx.connected[0], ctx.target.port, ctx.timeout)]


def _run_http(ctx: Context) -> list[CheckResult]:
    target = ctx.target
    return [
        checks.check_http(
            target.host,
            ctx.connected[0],
            target.port,
            ctx.timeout,
            use_tls=ctx.tls,
            path=target.path or "/",
        )
    ]


REGISTRY = [
    CheckSpec("local", Layer.LOCAL, None, _run_local),
    CheckSpec("dns", Layer.RESOLUTION, "local", _run_dns),
    CheckSpec("tcp", Layer.TRANSPORT, "dns", _run_tcp),
    CheckSpec("tls", Layer.SECURITY, "tcp", _run_tls, enabled=lambda ctx: ctx.tls),
    CheckSpec("http", Layer.APPLICATION, "tls", _run_http, enabled=lambda ctx: ctx.http),
]
