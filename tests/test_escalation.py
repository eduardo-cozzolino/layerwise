"""The ticket report: a pure function, so fixed inputs and a fixed clock."""

from datetime import datetime, timezone

import pytest

from layerwise.escalation import build_report
from layerwise.models import CheckResult, Status
from layerwise.registry import Context
from layerwise.targets import Target

NOW = datetime(2026, 10, 18, 14, 3, 22, tzinfo=timezone.utc)
TARGET = Target("203.0.113.80", 3389)
IT_RESET = "È stata forzata la chiusura di una connessione esistente dall'host remoto"


def report(results, skipped=(), tried=("203.0.113.80",)):
    ctx = Context(target=TARGET, timeout=2, tls=False, http=False)
    ctx.skipped, ctx.tried = list(skipped), list(tried)
    return build_report([(TARGET, results, ctx)], NOW)


LOCAL_OK = CheckResult("LOCAL", Status.OK, "192.0.2.10 via Wi-Fi, gateway 192.0.2.1")
DNS_SKIP = CheckResult("DNS", Status.SKIP, "target is an IP address, nothing to resolve")


def test_all_ok():
    text = report([LOCAL_OK, DNS_SKIP, CheckResult("TCP IPv4", Status.OK, "connected")])
    assert text.splitlines()[0] == "VERDICT: OK - no escalation needed"


def test_only_warnings():
    slow = CheckResult("DNS", Status.WARN, "resolved, slowly", hint="Slow DNS server.")
    text = report([LOCAL_OK, slow])
    assert (
        text.splitlines()[0] == "VERDICT: WARN at DNS -> suggested team: network (latency or path)"
    )


@pytest.mark.parametrize(
    ("result", "team"),
    [
        (
            CheckResult("TCP IPv4", Status.WARN, "slowly", details={"reason": "slow"}),
            "network (latency or path)",
        ),
        (
            # A failure downgraded to a warning by the runner keeps its original reason.
            CheckResult("TCP IPv6", Status.WARN, "no route", details={"reason": "unreachable"}),
            "network (IPv6)",
        ),
        (
            CheckResult("TCP IPv6", Status.WARN, "no answer", details={"reason": "timeout"}),
            "network (IPv6)",
        ),
    ],
    ids=["tcp-slow", "ipv6-unreachable", "ipv6-timeout"],
)
def test_network_warnings(result, team):
    text = report([LOCAL_OK, result])
    assert text.splitlines()[0] == f"VERDICT: WARN at {result.name} -> suggested team: {team}"


@pytest.mark.parametrize(
    ("result", "team"),
    [
        (CheckResult("LOCAL", Status.FAIL, "APIPA"), "desktop support (this PC or its LAN/Wi-Fi)"),
        (CheckResult("DNS", Status.FAIL, "cannot resolve"), "DNS"),
        (
            CheckResult("TCP IPv4", Status.FAIL, "no answer", details={"reason": "timeout"}),
            "firewall",
        ),
        (
            CheckResult("TCP IPv4", Status.FAIL, "no route", details={"reason": "unreachable"}),
            "firewall",
        ),
        (
            CheckResult("TCP IPv4", Status.FAIL, "refused", details={"reason": "refused"}),
            "service owner",
        ),
        (CheckResult("TLS", Status.FAIL, "certificate rejected"), "site/certificate owner"),
        (CheckResult("HTTP", Status.FAIL, "503 Service Unavailable"), "application"),
    ],
    ids=["local", "dns", "tcp-timeout", "tcp-unreachable", "tcp-refused", "tls", "http"],
)
def test_first_failure_decides_the_team(result, team):
    text = report([LOCAL_OK, result] if result.name != "LOCAL" else [result])
    assert text.splitlines()[0] == f"VERDICT: FAIL at {result.name} -> suggested team: {team}"


def test_failure_beats_an_earlier_warning():
    warn = CheckResult("DNS", Status.WARN, "slow")
    fail = CheckResult("TCP IPv4", Status.FAIL, "no answer", details={"reason": "timeout"})
    assert report([LOCAL_OK, warn, fail]).startswith("VERDICT: FAIL at TCP IPv4")


def test_header_lines():
    lines = report([LOCAL_OK, DNS_SKIP]).splitlines()
    assert "Date:    2026-10-18 14:03:22 UTC" in lines
    assert "Local:   192.0.2.10 via Wi-Fi, gateway 192.0.2.1" in lines
    assert "Target:  203.0.113.80:3389" in lines
    assert "Tried:   203.0.113.80" in lines


def test_skipped_check_names_the_failed_dependency():
    fail = CheckResult("TCP IPv4", Status.FAIL, "no answer", details={"reason": "timeout"})
    text = report([LOCAL_OK, DNS_SKIP, fail], skipped=[("tls", "tcp"), ("http", "tcp")])
    assert "TLS             -  not tested: tcp failed" in text
    assert "HTTP            -  not tested: tcp failed" in text


def test_italian_os_error_stays_ascii():
    reset = CheckResult(
        "TCP IPv4",
        Status.FAIL,
        "connection to 203.0.113.80:3389 failed (ConnectionResetError, WSAECONNRESET)",
        duration_ms=12.3,
        details={"os_error": IT_RESET, "reason": "other"},
    )
    text = report([LOCAL_OK, DNS_SKIP, reset])
    assert text.isascii()
    assert "os_error: E stata forzata la chiusura" in text
    assert "12 ms" in text


def test_several_targets_are_separated():
    ctx = Context(target=TARGET, timeout=2, tls=False, http=False)
    text = build_report([(TARGET, [LOCAL_OK], ctx), (TARGET, [LOCAL_OK], ctx)], NOW)
    assert text.count("VERDICT:") == 2
    assert "-" * 72 in text
