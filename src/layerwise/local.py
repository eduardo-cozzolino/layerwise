"""Layer 0: the machine itself. Does it have an address, and a route out?

The source address comes from a connected UDP socket: connect() on UDP sends no
packet, it only asks the kernel which route and source address it would use.

Gateway, DNS servers and interface name come from structured data, never from the
translated text of a command: PowerShell as JSON on Windows, the kernel's routing
tables in /proc and /etc/resolv.conf on Linux. Elsewhere, or when they cannot be
collected reliably, they are reported as missing, with the reason, not as a failure.
"""

from __future__ import annotations

import functools
import ipaddress
import json
import shutil
import socket
import subprocess
import sys
import time

from layerwise.models import CheckResult, Status
from layerwise.text import to_ascii

# Destinations for the default-route probe when the target is a name (nothing is sent to them).
PROBE_ADDRESSES = [(socket.AF_INET, "1.1.1.1"), (socket.AF_INET6, "2606:4700:4700::1111")]
PROBE_PORT = 53
POWERSHELL_TIMEOUT = 5.0
APIPA = ipaddress.ip_network("169.254.0.0/16")
FAMILY_LABELS = {socket.AF_INET: "IPv4", socket.AF_INET6: "IPv6"}

PROC_ROUTE = "/proc/net/route"
PROC_IPV6_ROUTE = "/proc/net/ipv6_route"
RESOLV_CONF = "/etc/resolv.conf"
RTF_UP_GATEWAY = 0x0001 | 0x0002  # route flags: RTF_UP, RTF_GATEWAY (it has a next hop)

# One object per interface: alias, its addresses, its default routes (next hop and total
# metric, RouteMetric + InterfaceMetric, the number Windows compares), its DNS servers.
# UTF-8 output: PowerShell 5.1 would otherwise write in the OEM code page (cp850 in Italy).
POWERSHELL_SCRIPT = """
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
$routes = Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue
$dns = Get-DnsClientServerAddress -ErrorAction SilentlyContinue
$items = Get-NetIPAddress -ErrorAction SilentlyContinue | Group-Object InterfaceIndex |
ForEach-Object {
  $index = [int]$_.Name
  [pscustomobject]@{
    alias = $_.Group[0].InterfaceAlias
    addresses = @($_.Group | ForEach-Object { $_.IPAddress })
    gateways = @($routes | Where-Object InterfaceIndex -eq $index | ForEach-Object {
      [pscustomobject]@{ next_hop = $_.NextHop; metric = $_.RouteMetric + $_.InterfaceMetric }
    })
    dns = @($dns | Where-Object InterfaceIndex -eq $index | ForEach-Object { $_.ServerAddresses })
  }
}
ConvertTo-Json -InputObject @($items) -Depth 3 -Compress
"""


def _source_address(family: int, destination: str) -> str:
    """The local address the kernel would use towards destination. OSError if there is no route."""
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.connect((destination, PROBE_PORT))
        return sock.getsockname()[0].split("%")[0]


def _addresses(value: object) -> list[str]:
    """PowerShell arrays hold nulls (no IPv6 address) and on-link routes (a VPN, for example)
    have 0.0.0.0 or :: as next hop: keep only real addresses, without the %zone suffix."""
    items = value if isinstance(value, list) else [value]
    result = []
    for item in items:
        if not isinstance(item, str):
            continue
        address = item.split("%")[0]
        try:
            if ipaddress.ip_address(address).is_unspecified:
                continue
        except ValueError:
            continue
        if address not in result:
            result.append(address)
    return result


def _best_gateways(routes: object) -> list[str]:
    """The default gateway per family: with several default routes, the lowest total metric
    wins, as Windows decides. IPv4 first, then IPv6."""
    best: dict[int, tuple[int, str]] = {}
    for route in routes if isinstance(routes, list) else [routes]:
        if not isinstance(route, dict):
            continue
        hops = _addresses(route.get("next_hop"))
        metric = route.get("metric")
        if not hops or not isinstance(metric, int):
            continue
        version = ipaddress.ip_address(hops[0]).version
        if version not in best or metric < best[version][0]:
            best[version] = (metric, hops[0])
    return [best[version][1] for version in sorted(best)]


@functools.lru_cache(maxsize=1)
def network_config() -> tuple[tuple[dict, ...] | None, str | None]:
    """(interfaces, None), or (None, why they are missing). Cached: one PowerShell per run."""
    if sys.platform != "win32":
        return None, f"not collected on {sys.platform}: only Windows and Linux are supported"
    executable = shutil.which("powershell")
    if executable is None:
        return None, "not collected: powershell not found"
    try:
        completed = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-Command", POWERSHELL_SCRIPT],
            capture_output=True,
            timeout=POWERSHELL_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return None, f"not collected: PowerShell did not answer within {POWERSHELL_TIMEOUT:g} s"
    except OSError as exc:
        return None, f"not collected: PowerShell could not start ({type(exc).__name__})"
    if completed.returncode != 0:
        return None, f"not collected: PowerShell exited with code {completed.returncode}"
    try:
        data = json.loads(completed.stdout.decode("utf-8-sig", errors="replace"))
    except ValueError:
        return None, "not collected: PowerShell output is not valid JSON"
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return None, "not collected: unexpected PowerShell output"
    interfaces = tuple(
        {
            "alias": str(item.get("alias") or ""),
            "addresses": _addresses(item.get("addresses")),
            "gateways": _best_gateways(item.get("gateways")),
            "dns": _addresses(item.get("dns")),
        }
        for item in data
        if isinstance(item, dict)
    )
    return interfaces, None


# Linux: the kernel's own tables, read as files. No command to run, no translated text.
#
# With several default routes the lowest metric wins. That is the kernel's choice in the
# usual case, not with policy routing (several routing tables, as some VPNs set up): there
# the rules decide which table is used, and these files do not show that decision.


def _best_default(candidates: list[tuple[int, str, str]]) -> tuple[str, str] | None:
    """(interface, gateway) of the (metric, interface, gateway) with the lowest metric."""
    if not candidates:
        return None
    _, interface, gateway = min(candidates, key=lambda candidate: candidate[0])
    return interface, gateway


def parse_proc_route(text: str) -> tuple[str, str] | None:
    """The IPv4 default route in /proc/net/route, as (interface, gateway).

    Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask ...; addresses are hex
    in host byte order (little-endian on x86 and ARM), the metric is decimal.
    """
    candidates = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8 or fields[1] != "00000000" or fields[7] != "00000000":
            continue
        try:
            flags, metric = int(fields[3], 16), int(fields[6])
            gateway = ipaddress.IPv4Address(int.from_bytes(bytes.fromhex(fields[2]), "little"))
        except ValueError:
            continue
        if flags & RTF_UP_GATEWAY == RTF_UP_GATEWAY and not gateway.is_unspecified:
            candidates.append((metric, fields[0], str(gateway)))
    return _best_default(candidates)


def parse_proc_ipv6_route(text: str) -> tuple[str, str] | None:
    """The IPv6 default route in /proc/net/ipv6_route, as (interface, gateway).

    No header. Columns: destination, prefix length, source, prefix length, next hop, metric,
    refcount, use, flags, interface; addresses in network byte order, numbers in hex.
    """
    candidates = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10 or fields[0] != "0" * 32 or fields[1] != "00":
            continue
        try:
            metric, flags = int(fields[5], 16), int(fields[8], 16)
            gateway = ipaddress.IPv6Address(bytes.fromhex(fields[4]))
        except ValueError:
            continue
        if flags & RTF_UP_GATEWAY == RTF_UP_GATEWAY and not gateway.is_unspecified:
            candidates.append((metric, fields[9], str(gateway)))
    return _best_default(candidates)


def parse_resolv_conf(text: str) -> list[str]:
    """The nameserver addresses, in order; comments and other options are ignored."""
    servers = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "nameserver":
            servers.append(fields[1])
    return _addresses(servers)


def _read(path: str) -> tuple[str | None, str | None]:
    """(content, None) or (None, why it could not be read): the exception type, never its
    translated message."""
    try:
        with open(path, encoding="ascii", errors="replace") as file:
            return file.read(), None
    except OSError as exc:
        return None, f"{path} not readable ({type(exc).__name__})"


def linux_config(versions: set[int]) -> tuple[str | None, list[str] | None, list[str] | None, str]:
    """(interface, gateways, DNS servers, note) for the IP versions in use.

    Gateways and DNS servers are None when their file cannot be read, and the note says why.
    A missing ipv6_route only means IPv6 is disabled in the kernel: no IPv6 gateway, no note.
    """
    notes = []
    defaults: dict[int, tuple[str, str] | None] = {}
    route_text, problem = _read(PROC_ROUTE)
    if problem:
        notes.append(problem)
    elif 4 in versions:
        defaults[4] = parse_proc_route(route_text or "")
    if 6 in versions:
        ipv6_text, _ = _read(PROC_IPV6_ROUTE)
        defaults[6] = parse_proc_ipv6_route(ipv6_text or "")
    found = [route for route in defaults.values() if route is not None]

    resolv_text, problem = _read(RESOLV_CONF)
    if problem:
        notes.append(problem)

    interface = found[0][0] if found else None
    gateways = None if route_text is None else [gateway for _, gateway in found]
    dns = None if resolv_text is None else parse_resolv_conf(resolv_text)
    note = "; ".join(f"not collected: {problem}" for problem in notes)
    return interface, gateways, dns, note


def _is_routable(address: str) -> bool:
    """An address that can talk beyond the link: not loopback, not APIPA, not fe80::."""
    ip = ipaddress.ip_address(address)
    return not (ip.is_loopback or ip.is_link_local)


def _interface_for(address: str, interfaces: tuple[dict, ...]) -> dict | None:
    return next((i for i in interfaces if address in i["addresses"]), None)


def check_local(host: str) -> CheckResult:
    """Source address and outgoing interface towards host (an IP) or the internet (a name)."""
    start = time.perf_counter()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        probes = [(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, host)]
    else:
        probes = PROBE_ADDRESSES

    sources: dict[int, str] = {}
    errors: list[str] = []
    for family, destination in probes:
        try:
            sources[family] = _source_address(family, destination)
        except OSError as exc:
            errors.append(f"{FAMILY_LABELS[family]}: {exc}")
    usable = {f: a for f, a in sources.items() if not ipaddress.ip_address(a).is_unspecified}

    # Only the gateways of the families that were probed (an IPv4 target: the IPv4 gateway).
    versions = {ipaddress.ip_address(a).version for a in usable.values()}
    interfaces: tuple[dict, ...] | None = None
    alias: str | None
    gateways: list[str] | None
    dns_servers: list[str] | None
    if sys.platform.startswith("linux"):
        alias, gateways, dns_servers, linux_note = linux_config(versions)
        note: str | None = linux_note or None
    else:
        interfaces, note = network_config()
        first = next(iter(usable.values()), None)
        interface = _interface_for(first, interfaces) if first and interfaces else None
        if interfaces is not None and note is None and interface is None and first:
            note = f"no interface found with address {first}"
        alias = interface["alias"] if interface else None
        gateways = (
            [g for g in interface["gateways"] if ipaddress.ip_address(g).version in versions]
            if interface
            else None
        )
        dns_servers = interface["dns"] if interface else None

    details: dict = {
        "local_addresses": list(usable.values()),
        "interface": to_ascii(alias) if alias else None,
        "gateways": gateways,
        "dns_servers": dns_servers,
    }
    if note:
        details["network_note"] = note
    if errors:
        details["os_error"] = "; ".join(errors)
    duration = round((time.perf_counter() - start) * 1000, 1)

    apipa = [a for a in usable.values() if ipaddress.ip_address(a) in APIPA]
    # Without PowerShell data we cannot tell "no address" from "no default route".
    has_any_address = interfaces is None or any(
        _is_routable(a) for i in interfaces for a in i["addresses"]
    )

    if apipa:
        return CheckResult(
            "LOCAL",
            Status.FAIL,
            f"self-assigned address {apipa[0]} (APIPA): no DHCP answer",
            hint=(
                "The PC gave itself a 169.254.x.x address because no DHCP server answered. "
                "Check the cable or the Wi-Fi association, then the DHCP server or the switch "
                "port (VLAN)."
            ),
            duration_ms=duration,
            details=details,
        )
    if not usable and not has_any_address:
        return CheckResult(
            "LOCAL",
            Status.FAIL,
            "no IP address on any interface",
            hint="The PC is not connected: check the cable, the Wi-Fi or the network adapter.",
            duration_ms=duration,
            details=details,
        )
    if not usable and ip is not None:
        return CheckResult(
            "LOCAL",
            Status.FAIL,
            f"no route to {host}",
            hint=(
                "The routing table of this PC has no route to that network: no default "
                "gateway, or a VPN that is not connected."
            ),
            duration_ms=duration,
            details=details,
        )
    if not usable:
        return CheckResult(
            "LOCAL",
            Status.WARN,
            "no default route: only internal destinations reachable",
            hint=(
                "Normal on corporate networks that reach the internet through a proxy. "
                "Otherwise the default gateway is missing: check the DHCP lease or the VPN."
            ),
            duration_ms=duration,
            details=details,
        )

    summary = ", ".join(usable.values())
    if details["interface"]:
        summary += f" via {details['interface']}"
    if details["gateways"]:
        summary += ", gateway " + ", ".join(details["gateways"])
    if details["dns_servers"]:
        summary += ", DNS " + ", ".join(details["dns_servers"])
    return CheckResult("LOCAL", Status.OK, summary, duration_ms=duration, details=details)
