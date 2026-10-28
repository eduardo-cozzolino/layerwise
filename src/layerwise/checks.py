"""The individual network checks.

Every check returns a CheckResult and never raises: a failure is a result,
and its hint explains what that failure tells you about the network.

Summaries and hints are English ASCII built from the exception type and its
error code only. The operating system's own message is translated into the
Windows language (and its code page), so it goes in details["os_error"].
"""

from __future__ import annotations

import errno
import http.client
import ipaddress
import socket
import ssl
import time

from layerwise import __version__
from layerwise.models import CheckResult, Status
from layerwise.text import ascii_host, to_ascii

SLOW_DNS_MS = 500
SLOW_TCP_MS = 200
CERT_WARN_DAYS = 14

# POSIX errno values plus the Winsock codes Windows uses for the same errors.
UNREACHABLE_ERRNOS = {errno.ENETUNREACH, errno.EHOSTUNREACH, 10051, 10065}

# getaddrinfo error codes differ between platforms, so they are read from the socket module.
# On Windows EAI_NODATA is the same code as EAI_NONAME: setdefault keeps the first text.
RESOLVER_ERRORS: dict[int, str] = {}
for _name, _text in [
    ("EAI_NONAME", "name not found"),
    ("EAI_AGAIN", "temporary failure, the DNS server did not answer"),
    ("EAI_FAIL", "the DNS server reported a permanent failure"),
    ("EAI_NODATA", "the name exists but has no address"),
]:
    if hasattr(socket, _name):
        RESOLVER_ERRORS.setdefault(getattr(socket, _name), _text)
RESOLVER_ERRORS.setdefault(11004, "the name exists but has no address")  # Winsock WSANO_DATA

# OpenSSL X.509 verification codes (verify_code on SSLCertVerificationError).
CERT_ERRORS = {
    10: "certificate has expired",
    18: "self-signed certificate",
    19: "self-signed root in the chain, not trusted",
    20: "issuer certificate not found (missing intermediate or unknown CA)",
    21: "unable to verify the first certificate",
    62: "certificate issued for a different name",
}
ISSUER_NOT_FOUND = 20

FAMILY_LABELS: dict[int, str] = {socket.AF_INET: "IPv4", socket.AF_INET6: "IPv6"}


def _error_label(exc: BaseException) -> str:
    """'ConnectionResetError, WSAECONNRESET': the exception type and the symbolic errno name."""
    label = type(exc).__name__
    code = getattr(exc, "errno", None)
    if isinstance(code, int):
        label += ", " + errno.errorcode.get(code, f"errno {code}")
    return label


def _os_details(exc: BaseException) -> dict:
    return {"os_error": str(exc)}


def _elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 1)


def _hostport(address: str, port: int) -> str:
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def check_dns(host: str) -> tuple[CheckResult, list[tuple[int, str]]]:
    """Resolve host. Returns the result and the unique (family, address) pairs in resolver order."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        result = CheckResult("DNS", Status.SKIP, "target is an IP address, nothing to resolve")
        return result, [(family, host)]

    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        name = ascii_host(host)
        known = RESOLVER_ERRORS.get(exc.errno) if exc.errno is not None else None
        reason = known or f"resolver error {exc.errno}"
        result = CheckResult(
            "DNS",
            Status.FAIL,
            f"cannot resolve {name} ({reason})",
            hint=(
                "The name does not exist or your DNS server is not answering. Check the "
                f"spelling, then compare with a public resolver: nslookup {name} 1.1.1.1"
            ),
            duration_ms=_elapsed_ms(start),
            details=_os_details(exc),
        )
        return result, []
    duration = _elapsed_ms(start)

    addresses: list[tuple[int, str]] = []
    for family, _, _, _, sockaddr in infos:
        entry = (family, str(sockaddr[0]))
        if family in FAMILY_LABELS and entry not in addresses:
            addresses.append(entry)

    summary = "resolved to " + ", ".join(address for _, address in addresses)
    details = {"addresses": [address for _, address in addresses]}
    if duration > SLOW_DNS_MS:
        result = CheckResult(
            "DNS",
            Status.WARN,
            summary,
            hint=(
                f"Resolution took more than {SLOW_DNS_MS} ms: the DNS server is slow or far "
                "away, and every new connection pays this delay."
            ),
            duration_ms=duration,
            details=details,
        )
    else:
        result = CheckResult("DNS", Status.OK, summary, duration_ms=duration, details=details)
    return result, addresses


def check_tcp(address: str, family: int, port: int, timeout: float) -> CheckResult:
    """Open (and close) a TCP connection: proves the three-way handshake completes."""
    name = f"TCP {FAMILY_LABELS[family]}"
    endpoint = _hostport(address, port)
    start = time.perf_counter()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            pass
    except ConnectionRefusedError as exc:
        return CheckResult(
            name,
            Status.FAIL,
            f"connection refused by {endpoint}",
            hint=(
                "The host answered with a TCP reset: it is reachable, but nothing is listening "
                f"on port {port}, or a firewall is actively rejecting. Check that the service is "
                "running and bound to the right interface."
            ),
            duration_ms=_elapsed_ms(start),
            details={**_os_details(exc), "reason": "refused"},
        )
    except TimeoutError as exc:
        return CheckResult(
            name,
            Status.FAIL,
            f"no answer from {endpoint} within {timeout:g} s",
            hint=(
                "Not even a reset came back: packets are probably dropped silently by a "
                "firewall, ACL or security group, or the host is down. Compare with another "
                "port on the same host, or run a traceroute."
            ),
            duration_ms=_elapsed_ms(start),
            details={**_os_details(exc), "reason": "timeout"},
        )
    except OSError as exc:
        if exc.errno in UNREACHABLE_ERRNOS:
            return CheckResult(
                name,
                Status.FAIL,
                f"no route to {address}",
                hint=(
                    "Your machine has no route to this network. For IPv6 this usually means "
                    "your connection has no IPv6 connectivity at all."
                ),
                duration_ms=_elapsed_ms(start),
                details={**_os_details(exc), "reason": "unreachable"},
            )
        return CheckResult(
            name,
            Status.FAIL,
            f"connection to {endpoint} failed ({_error_label(exc)})",
            duration_ms=_elapsed_ms(start),
            details={**_os_details(exc), "reason": "other"},
        )

    duration = _elapsed_ms(start)
    if duration > SLOW_TCP_MS:
        return CheckResult(
            name,
            Status.WARN,
            f"connected to {endpoint}, but slowly",
            hint=(
                f"The handshake took more than {SLOW_TCP_MS} ms: high latency on the path "
                "(distance, congestion, VPN). Applications will feel sluggish."
            ),
            duration_ms=duration,
            details={"reason": "slow"},
        )
    return CheckResult(name, Status.OK, f"connected to {endpoint}", duration_ms=duration)


def _issuer_name(cert: dict) -> str:
    fields = {key: value for rdn in cert.get("issuer", ()) for key, value in rdn}
    return fields.get("organizationName") or fields.get("commonName") or "unknown issuer"


def summarize_certificate(
    version: str | None, cert: dict, now: float, duration_ms: float | None = None
) -> CheckResult:
    """Turn a verified certificate into a result. Pure function, so it is easy to test."""
    expires = ssl.cert_time_to_seconds(cert["notAfter"])
    days_left = int((expires - now) // 86400)
    issuer = _issuer_name(cert)
    details = {
        "version": version,
        "issuer": issuer,
        "not_after": cert["notAfter"],
        "days_left": days_left,
    }
    summary = (
        f"{version}, certificate valid for {days_left} more days, issued by {to_ascii(issuer)}"
    )
    if days_left < CERT_WARN_DAYS:
        return CheckResult(
            "TLS",
            Status.WARN,
            summary,
            hint=(
                "The certificate expires soon. Once it does, every client will refuse the "
                "connection: renew it now."
            ),
            duration_ms=duration_ms,
            details=details,
        )
    return CheckResult("TLS", Status.OK, summary, duration_ms=duration_ms, details=details)


def check_tls(host: str, address: str, port: int, timeout: float) -> CheckResult:
    """Complete a TLS handshake against address, validating the certificate for host."""
    context = ssl.create_default_context()
    start = time.perf_counter()
    try:
        with socket.create_connection((address, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                version = tls.version()
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        reason = CERT_ERRORS.get(exc.verify_code)
        if reason is None:
            reason = f"verify code {exc.verify_code}: {to_ascii(exc.verify_message or '')}"
        inspect = (
            f"openssl s_client -connect {_hostport(address, port)} -servername {ascii_host(host)}"
        )
        if exc.verify_code == ISSUER_NOT_FOUND:
            # Windows fetches missing roots on demand for its own clients; Python's ssl only
            # reads the roots already in the store, so a valid site can fail here alone.
            url = f"https://{ascii_host(host)}" + ("" if port == 443 else f":{port}")
            hint = (
                "The root CA may be missing from the local certificate store: on Windows, "
                "Python does not download it automatically as Edge and curl do. Open the site "
                f"once in Edge or run: Invoke-WebRequest {url} and retry. If it still fails, "
                f"the chain really is incomplete. Inspect it with: {inspect}"
            )
        else:
            hint = (
                "The certificate is expired, self-signed, issued for a different name or "
                f"missing its intermediate chain. Inspect it with: {inspect}"
            )
        return CheckResult(
            "TLS",
            Status.FAIL,
            f"certificate rejected: {reason}",
            hint=hint,
            duration_ms=_elapsed_ms(start),
            details={"verify_code": exc.verify_code, "verify_message": exc.verify_message},
        )
    except ssl.SSLError as exc:
        # reason is an OpenSSL code such as WRONG_VERSION_NUMBER, never translated.
        return CheckResult(
            "TLS",
            Status.FAIL,
            f"handshake failed: {exc.reason or _error_label(exc)}",
            hint=(
                "The port may not speak TLS at all, or client and server share no protocol "
                "version or cipher."
            ),
            duration_ms=_elapsed_ms(start),
            details=_os_details(exc),
        )
    except OSError as exc:
        return CheckResult(
            "TLS",
            Status.FAIL,
            f"connection lost during the handshake ({_error_label(exc)})",
            hint=(
                "TCP works but the TLS exchange did not complete: a proxy, IPS or a different "
                "service on this port may be interfering."
            ),
            duration_ms=_elapsed_ms(start),
            details=_os_details(exc),
        )
    if not cert:
        # Not expected with CERT_REQUIRED, which refuses a handshake without a certificate:
        # reported as a failure all the same, rather than trusting a connection unverified.
        return CheckResult(
            "TLS",
            Status.FAIL,
            "handshake completed without a server certificate",
            hint=(
                "The server identity could not be verified, so the connection cannot be "
                "trusted. Inspect what the server sends with: "
                f"openssl s_client -connect {_hostport(address, port)} "
                f"-servername {ascii_host(host)}"
            ),
            duration_ms=_elapsed_ms(start),
            details={"version": version},
        )
    return summarize_certificate(version, cert, time.time(), _elapsed_ms(start))


class _NamedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a fixed address, with SNI and certificate check for the name.

    http.client would use one host for both: the connection must go to the address TCP
    verified, the certificate must be valid for the name the user asked for.
    """

    def __init__(self, address: str, port: int, server_name: str, timeout: float) -> None:
        self._tls_context = ssl.create_default_context()
        super().__init__(address, port, timeout=timeout, context=self._tls_context)
        self._server_name = server_name

    def connect(self) -> None:
        http.client.HTTPConnection.connect(self)
        self.sock = self._tls_context.wrap_socket(self.sock, server_hostname=self._server_name)


def _host_header(host: str, port: int, use_tls: bool) -> str:
    """The Host header for the name: punycode, IPv6 in brackets, the port only if not default."""
    name = f"[{host}]" if ":" in host else ascii_host(host)
    return name if port == (443 if use_tls else 80) else f"{name}:{port}"


def check_http(
    host: str, address: str, port: int, timeout: float, use_tls: bool, path: str = "/"
) -> CheckResult:
    """Send GET path to address (the one TCP verified) for host, and look at the status code."""
    if use_tls:
        connection: http.client.HTTPConnection = _NamedHTTPSConnection(address, port, host, timeout)
    else:
        connection = http.client.HTTPConnection(address, port, timeout=timeout)
    headers = {"Host": _host_header(host, port, use_tls), "User-Agent": f"layerwise/{__version__}"}
    start = time.perf_counter()
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        status, reason = response.status, response.reason
        location = response.getheader("Location")
        server = response.getheader("Server")
    except (OSError, http.client.HTTPException) as exc:
        return CheckResult(
            "HTTP",
            Status.FAIL,
            f"request failed ({_error_label(exc)})",
            hint=(
                "The connection works but no valid HTTP answer came back. Is this port "
                "really serving HTTP?"
            ),
            duration_ms=_elapsed_ms(start),
            details=_os_details(exc),
        )
    finally:
        connection.close()

    # Reason and Location come from the server (decoded as latin-1): made ASCII for the summary,
    # kept as sent in details.
    duration = _elapsed_ms(start)
    summary = f"{status} {to_ascii(reason)}"
    if location:
        summary += f" -> {to_ascii(location)}"
    details = {"status": status, "server": server, "location": location}

    if status >= 500:
        return CheckResult(
            "HTTP",
            Status.FAIL,
            summary,
            hint=(
                "The network path is fine: the problem is the application or a backend "
                "behind it. Check the server logs."
            ),
            duration_ms=duration,
            details=details,
        )
    if status >= 400:
        return CheckResult(
            "HTTP",
            Status.WARN,
            summary,
            hint=(
                "The server answered but refused the request. This is usually not a network "
                "issue: check the URL, authentication or access rules."
            ),
            duration_ms=duration,
            details=details,
        )
    return CheckResult("HTTP", Status.OK, summary, duration_ms=duration, details=details)
