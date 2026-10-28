"""The runner's decisions, with the checks replaced by fakes."""

import socket

import pytest

from layerwise import checks, local
from layerwise.models import CheckResult, Status
from layerwise.runner import run_checks, run_target
from layerwise.targets import Target

V4, V6 = "192.0.2.10", "2001:db8::10"


@pytest.fixture(autouse=True)
def fake_local(monkeypatch):
    """Layer 0 always passes here: no real sockets, no PowerShell."""
    monkeypatch.setattr(local, "check_local", lambda host: CheckResult("LOCAL", Status.OK, "local"))


@pytest.fixture
def fake_network(monkeypatch):
    """Both families resolve; each check's outcome is set per test."""
    state = {"tcp": {V4: Status.OK, V6: Status.OK}, "tls": Status.OK, "calls": []}

    def dns(host):
        result = CheckResult("DNS", Status.OK, "resolved")
        return result, [(socket.AF_INET, V4), (socket.AF_INET6, V6)]

    def tcp(address, family, port, timeout):
        state["calls"].append("tcp")
        return CheckResult(f"TCP {address}", state["tcp"][address], "tcp", hint="Base hint.")

    def tls(host, address, port, timeout):
        state["calls"].append("tls")
        return CheckResult("TLS", state["tls"], "tls")

    def http(host, port, timeout, use_tls):
        state["calls"].append("http")
        return CheckResult("HTTP", Status.OK, "200 OK")

    monkeypatch.setattr(checks, "check_dns", dns)
    monkeypatch.setattr(checks, "check_tcp", tcp)
    monkeypatch.setattr(checks, "check_tls", tls)
    monkeypatch.setattr(checks, "check_http", http)
    return state


def test_all_layers_run_on_443(fake_network):
    results = run_checks(Target("example.com", 443))
    assert [r.name for r in results] == ["LOCAL", "DNS", f"TCP {V4}", f"TCP {V6}", "TLS", "HTTP"]


def test_other_ports_stop_at_tcp(fake_network):
    results = run_checks(Target("example.com", 22))
    assert fake_network["calls"] == ["tcp", "tcp"]
    assert len(results) == 4


def test_broken_ipv6_is_only_a_warning(fake_network):
    fake_network["tcp"][V6] = Status.FAIL
    results = run_checks(Target("example.com", 22))
    v6 = results[3]
    assert v6.status is Status.WARN
    assert v6.hint.startswith("Base hint.")
    assert "fall back" in v6.hint


def test_no_tls_when_tcp_fails_everywhere(fake_network):
    fake_network["tcp"] = {V4: Status.FAIL, V6: Status.FAIL}
    results = run_checks(Target("example.com", 443))
    assert "tls" not in fake_network["calls"]
    assert all(r.status is Status.FAIL for r in results[2:])


def test_no_http_when_tls_fails(fake_network):
    fake_network["tls"] = Status.FAIL
    run_checks(Target("example.com", 443))
    assert "http" not in fake_network["calls"]


def test_flags_override_port_defaults(fake_network):
    run_checks(Target("example.com", 8443), tls=True, http=True)
    assert fake_network["calls"][-2:] == ["tls", "http"]


def test_ip_target_skips_dns_but_still_tests_tcp(monkeypatch):
    # The real check_dns: an IP literal needs no network, it is returned as the only address.
    seen = []

    def tcp(address, family, port, timeout):
        seen.append((address, family))
        return CheckResult("TCP IPv4", Status.OK, "tcp")

    monkeypatch.setattr(checks, "check_tcp", tcp)
    results = run_checks(Target("192.0.2.10", 22))
    assert [r.status for r in results] == [Status.OK, Status.SKIP, Status.OK]
    assert seen == [("192.0.2.10", socket.AF_INET)]


def test_dns_failure_stops_everything(monkeypatch):
    monkeypatch.setattr(
        checks, "check_dns", lambda host: (CheckResult("DNS", Status.FAIL, "nope"), [])
    )
    results = run_checks(Target("nope.invalid", 443))
    assert [r.name for r in results] == ["LOCAL", "DNS"]


def test_local_failure_stops_everything(fake_network, monkeypatch):
    monkeypatch.setattr(
        local, "check_local", lambda host: CheckResult("LOCAL", Status.FAIL, "APIPA")
    )
    results, ctx = run_target(Target("example.com", 443))
    assert [r.name for r in results] == ["LOCAL"]
    assert ctx.skipped == [("dns", "local"), ("tcp", "local"), ("tls", "local"), ("http", "local")]


def test_no_default_route_still_runs_dns(fake_network, monkeypatch):
    # Corporate network with a proxy: no default route is a warning, internal names still resolve.
    monkeypatch.setattr(
        local, "check_local", lambda host: CheckResult("LOCAL", Status.WARN, "no default route")
    )
    results = run_checks(Target("example.com", 22))
    assert [r.name for r in results][:2] == ["LOCAL", "DNS"]


def test_tried_lists_one_address_per_family(fake_network):
    _, ctx = run_target(Target("example.com", 22))
    assert ctx.tried == [V4, V6]
