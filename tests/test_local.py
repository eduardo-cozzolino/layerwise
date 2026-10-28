"""Layer 0 with fake sockets and a fake PowerShell: no network, no subprocess."""

import json
import shutil
import socket
import subprocess
import sys

import pytest

from layerwise import local
from layerwise.models import Status

WIFI = {
    "alias": "Wi-Fi",
    "addresses": ["fe80::1%12", "192.0.2.10", None],
    "gateways": [{"next_hop": "192.0.2.1", "metric": 35}],
    "dns": ["198.51.100.53"],
}
VPN = {
    "alias": "VPN",
    "addresses": ["203.0.113.5"],
    "gateways": [{"next_hop": "203.0.113.1", "metric": 5}],
    "dns": ["203.0.113.53"],
}
LOOPBACK = {"alias": "Loopback", "addresses": ["127.0.0.1", "::1"], "gateways": [], "dns": []}


@pytest.fixture(autouse=True)
def clear_cache():
    """network_config is cached for the whole run: each test starts from scratch."""
    local.network_config.cache_clear()
    yield
    local.network_config.cache_clear()


@pytest.fixture
def routes(monkeypatch):
    """Source address per family; a family missing from the dict has no route."""
    table = {socket.AF_INET: "192.0.2.10"}

    def source(family, destination):
        if family not in table:
            raise OSError(10051, "Impossibile raggiungere la rete è")
        return table[family]

    monkeypatch.setattr(local, "_source_address", source)
    return table


@pytest.fixture
def powershell(monkeypatch):
    """Pretend to be Windows with PowerShell; each test sets what PowerShell does."""
    state = {"stdout": json.dumps([WIFI, LOOPBACK]).encode(), "code": 0, "raise": None, "calls": 0}

    def run(args, capture_output, timeout):
        state["calls"] += 1
        if state["raise"] is not None:
            raise state["raise"]
        return subprocess.CompletedProcess(args, state["code"], state["stdout"], b"")

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(shutil, "which", lambda name: "powershell.exe")
    monkeypatch.setattr(subprocess, "run", run)
    return state


def test_normal_connection(routes, powershell):
    result = local.check_local("example.com")
    assert result.status is Status.OK
    assert result.summary == "192.0.2.10 via Wi-Fi, gateway 192.0.2.1, DNS 198.51.100.53"
    assert result.details["gateways"] == ["192.0.2.1"]


def test_apipa_is_a_failure(routes, powershell):
    routes[socket.AF_INET] = "169.254.7.7"
    result = local.check_local("example.com")
    assert result.status is Status.FAIL
    assert "APIPA" in result.summary
    assert "DHCP" in result.hint


def test_unspecified_source_and_no_address_is_a_failure(routes, powershell):
    routes[socket.AF_INET] = "0.0.0.0"
    powershell["stdout"] = json.dumps([LOOPBACK]).encode()
    result = local.check_local("example.com")
    assert result.status is Status.FAIL
    assert result.summary == "no IP address on any interface"


def test_ip_target_without_route_is_a_failure(routes, powershell):
    routes.clear()
    result = local.check_local("10.20.30.40")
    assert result.status is Status.FAIL
    assert result.summary == "no route to 10.20.30.40"


def test_name_without_default_route_is_a_warning(routes, powershell):
    routes.clear()
    result = local.check_local("intranet.example")
    assert result.status is Status.WARN
    assert result.summary == "no default route: only internal destinations reachable"


@pytest.mark.parametrize(
    ("setup", "note"),
    [
        (lambda ps: ps.update(code=1), "exited with code 1"),
        (lambda ps: ps.update(stdout=b"Get-NetRoute : errore"), "not valid JSON"),
        (
            lambda ps: ps.update({"raise": subprocess.TimeoutExpired("powershell", 5)}),
            "did not answer within 5 s",
        ),
        (lambda ps: ps.update({"raise": FileNotFoundError(2, "file")}), "could not start"),
    ],
    ids=["exit-code", "invalid-json", "timeout", "cannot-start"],
)
def test_powershell_problems_are_missing_data_not_failures(routes, powershell, setup, note):
    setup(powershell)
    result = local.check_local("example.com")
    assert result.status is Status.OK
    assert result.details["gateways"] is None
    assert note in result.details["network_note"]


def test_powershell_not_installed(routes, powershell, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    result = local.check_local("example.com")
    assert result.status is Status.OK
    assert result.details["network_note"] == "not collected: powershell not found"


def test_not_windows(routes, powershell, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    result = local.check_local("example.com")
    assert result.status is Status.OK
    assert result.summary == "192.0.2.10"
    assert "only Windows" in result.details["network_note"]
    assert powershell["calls"] == 0


def test_single_interface_object(routes, powershell):
    # ConvertTo-Json turns a one-element array into a bare object if -InputObject is not used.
    powershell["stdout"] = json.dumps(WIFI).encode()
    assert "via Wi-Fi" in local.check_local("example.com").summary


def test_accented_alias_is_ascii(routes, powershell):
    alias = "Connessione alla rete locale (LAN) è"
    powershell["stdout"] = json.dumps([{**WIFI, "alias": alias}]).encode("utf-8")
    result = local.check_local("example.com")
    assert result.summary.isascii()
    assert "via Connessione alla rete locale (LAN) e" in result.summary


def test_powershell_runs_once_per_run(routes, powershell):
    local.check_local("example.com")
    local.check_local("example.org")
    assert powershell["calls"] == 1


def test_gateway_follows_the_interface_of_the_source_address(routes, powershell):
    # Wi-Fi and VPN both have a default route. Windows picked the VPN (lower metric), and the
    # UDP probe shows it: the source address is the VPN one, so is the gateway.
    routes[socket.AF_INET] = "203.0.113.5"
    powershell["stdout"] = json.dumps([WIFI, VPN]).encode()
    result = local.check_local("example.com")
    assert result.details["interface"] == "VPN"
    assert result.details["gateways"] == ["203.0.113.1"]


def test_lowest_total_metric_wins_on_one_interface(routes, powershell):
    two_routes = [
        {"next_hop": "192.0.2.254", "metric": 291},
        {"next_hop": "192.0.2.1", "metric": 35},
        {"next_hop": "fe80::1", "metric": 296},
        {"next_hop": "0.0.0.0", "metric": 1},  # on-link default route: no next hop
    ]
    routes[socket.AF_INET6] = "2001:db8::10"
    wifi = {**WIFI, "addresses": ["192.0.2.10", "2001:db8::10"], "gateways": two_routes}
    powershell["stdout"] = json.dumps([wifi]).encode()
    result = local.check_local("example.com")
    assert result.details["gateways"] == ["192.0.2.1", "fe80::1"]


def test_ip_target_shows_only_the_gateway_of_its_family(routes, powershell):
    routes[socket.AF_INET6] = "2001:db8::10"
    routes_v4_v6 = [{"next_hop": "192.0.2.1", "metric": 35}, {"next_hop": "fe80::1", "metric": 296}]
    wifi = {**WIFI, "addresses": ["192.0.2.10", "2001:db8::10"], "gateways": routes_v4_v6}
    powershell["stdout"] = json.dumps([wifi]).encode()
    assert local.check_local("10.20.30.40").details["gateways"] == ["192.0.2.1"]


# Linux: /proc/net/route, /proc/net/ipv6_route and /etc/resolv.conf, as the kernel writes them.
PROC_ROUTE = "".join(
    "\t".join(row) + "\n"
    for row in [
        ["Iface", "Destination", "Gateway ", "Flags", "RefCnt", "Use", "Metric", "Mask", "", "MTU"],
        ["wlan0", "00000000", "FE0200C0", "0003", "0", "0", "600", "00000000", "0", "0"],
        ["eth0", "00000000", "010200C0", "0003", "0", "0", "100", "00000000", "0", "0"],
        ["eth1", "00000000", "020200C0", "0002", "0", "0", "1", "00000000", "0", "0"],
        ["tun0", "00000000", "00000000", "0001", "0", "0", "0", "00000000", "0", "0"],
        ["eth0", "000200C0", "00000000", "0001", "0", "0", "100", "00FFFFFF", "0", "0"],
    ]
)
ZERO = "0" * 32
PROC_IPV6_ROUTE = "".join(
    " ".join(row) + "\n"
    for row in [
        ["2001db8" + "0" * 25, "40", ZERO, "00", ZERO, "00000100", "1", "0", "00000001", "eth0"],
        [ZERO, "00", ZERO, "00", "fe80" + "0" * 27 + "1", "00000400", "1", "0", "00000003", "eth0"],
        [
            ZERO,
            "00",
            ZERO,
            "00",
            "fe80" + "0" * 27 + "2",
            "00000064",
            "1",
            "0",
            "00000003",
            "wlan0",
        ],
        [ZERO, "00", ZERO, "00", ZERO, "ffffffff", "1", "0", "00200200", "lo"],
    ]
)
RESOLV_CONF = """# Generated by NetworkManager
; nameserver 192.0.2.99
search example.com
nameserver 198.51.100.53
nameserver fe80::53%eth0
nameserver not-an-address
options edns0
"""


@pytest.fixture
def linux(monkeypatch, tmp_path):
    """Pretend to be Linux, with the three files in tmp_path; a test can remove one."""
    files = {
        "PROC_ROUTE": PROC_ROUTE,
        "PROC_IPV6_ROUTE": PROC_IPV6_ROUTE,
        "RESOLV_CONF": RESOLV_CONF,
    }
    paths = {}
    for name, content in files.items():
        path = tmp_path / name.lower()
        path.write_text(content, encoding="ascii")
        monkeypatch.setattr(local, name, str(path))
        paths[name] = path

    def no_subprocess(*args, **kwargs):
        raise AssertionError("no external command on Linux")

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(subprocess, "run", no_subprocess)
    return paths


def test_ipv4_default_route_lowest_metric_wins():
    # wlan0 (600) loses to eth0 (100); eth1 is not up, tun0 has no next hop, 192.0.2.0/24 is
    # not a default route.
    assert local.parse_proc_route(PROC_ROUTE) == ("eth0", "192.0.2.1")


def test_ipv6_default_route_lowest_metric_wins():
    # wlan0 (0x64) beats eth0 (0x400); the unreachable default on lo has no next hop.
    assert local.parse_proc_ipv6_route(PROC_IPV6_ROUTE) == ("wlan0", "fe80::2")


def test_no_default_route():
    assert local.parse_proc_route(PROC_ROUTE.splitlines()[0]) is None
    assert local.parse_proc_ipv6_route("") is None


def test_resolv_conf_nameservers():
    assert local.parse_resolv_conf(RESOLV_CONF) == ["198.51.100.53", "fe80::53"]


def test_linux_summary(routes, linux):
    result = local.check_local("example.com")
    assert result.status is Status.OK
    assert result.summary == "192.0.2.10 via eth0, gateway 192.0.2.1, DNS 198.51.100.53, fe80::53"
    assert "network_note" not in result.details


def test_linux_dual_stack_has_both_gateways(routes, linux):
    routes[socket.AF_INET6] = "2001:db8::10"
    assert local.check_local("example.com").details["gateways"] == ["192.0.2.1", "fe80::2"]


def test_linux_ipv4_target_shows_only_the_ipv4_gateway(routes, linux):
    routes[socket.AF_INET6] = "2001:db8::10"
    assert local.check_local("192.0.2.80").details["gateways"] == ["192.0.2.1"]


def test_linux_missing_files_are_missing_data_not_failures(routes, linux):
    linux["PROC_ROUTE"].unlink()
    linux["RESOLV_CONF"].unlink()
    result = local.check_local("example.com")
    assert result.status is Status.OK
    assert result.details["gateways"] is None
    assert result.details["dns_servers"] is None
    note = result.details["network_note"]
    assert note.count("not readable (FileNotFoundError)") == 2
    assert note.isascii()


def test_linux_without_ipv6_routes_is_not_a_problem(routes, linux):
    routes[socket.AF_INET6] = "2001:db8::10"
    linux["PROC_IPV6_ROUTE"].unlink()
    result = local.check_local("example.com")
    assert result.details["gateways"] == ["192.0.2.1"]
    assert "network_note" not in result.details
