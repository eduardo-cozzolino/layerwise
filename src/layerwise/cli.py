"""Command line entry point.

Exit codes: 0 everything fine, 1 at least one warning, 2 at least one failure.
That makes layerwise usable from scripts and monitoring jobs.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from layerwise import __version__
from layerwise.escalation import build_report
from layerwise.models import Status, worst_status
from layerwise.report import format_json, format_text, use_color
from layerwise.runner import run_target
from layerwise.targets import parse_target

EXIT_CODES = {Status.SKIP: 0, Status.OK: 0, Status.WARN: 1, Status.FAIL: 2}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="layerwise",
        description=(
            "Diagnose a network service layer by layer: local configuration (layer 0), DNS, "
            "TCP over IPv4 and IPv6, TLS and HTTP, with plain-language hints and an escalation "
            "report for tickets."
        ),
    )
    parser.add_argument(
        "targets", nargs="+", metavar="TARGET", help="host, host:port, [ipv6]:port or a URL"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=443, help="port for targets without one (default: 443)"
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=3.0, help="seconds per check (default: 3)"
    )
    parser.add_argument(
        "--tls",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="force or skip the TLS check (default: only on https and port 443)",
    )
    parser.add_argument(
        "--http",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="force or skip the HTTP check (default: on URLs and ports 80/443)",
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="print machine-readable JSON")
    output.add_argument(
        "--report", action="store_true", help="print a plain-text report to paste into a ticket"
    )
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        targets = [parse_target(text, default_port=args.port) for text in args.targets]
    except ValueError as exc:
        parser.error(str(exc))

    runs = [
        (target, *run_target(target, timeout=args.timeout, tls=args.tls, http=args.http))
        for target in targets
    ]
    reports = [(target, results) for target, results, _ in runs]

    # Output is ASCII already; this is the safety net. Redirected to a file on Windows,
    # stdout uses the ANSI code page (cp1252): escape what it cannot encode instead of crashing.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")

    if args.json:
        print(format_json(runs))
    elif args.report:
        print(build_report(runs, datetime.now(timezone.utc)))
    else:
        color = not args.no_color and use_color(sys.stdout)
        print("\n\n".join(format_text(target, results, color) for target, results in reports))

    overall = worst_status([result for _, results in reports for result in results])
    return EXIT_CODES[overall]
