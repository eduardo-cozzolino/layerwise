"""Parse what the user types into a host and a port.

Accepted forms: host, host:port, 1.2.3.4:port, an IPv6 address, [IPv6]:port
and URLs such as https://example.com:8443/path (people often paste URLs).
"""

from __future__ import annotations

from dataclasses import dataclass

from layerwise.text import ascii_host

SCHEME_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    scheme: str | None = None

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else ascii_host(self.host)
        return f"{host}:{self.port}"


def parse_target(text: str, default_port: int = 443) -> Target:
    text = text.strip()
    scheme = None

    if "://" in text:
        scheme, _, text = text.partition("://")
        scheme = scheme.lower()
        if scheme not in SCHEME_PORTS:
            raise ValueError(f"unsupported scheme: {scheme}")
        default_port = SCHEME_PORTS[scheme]
        text = text.split("/", 1)[0]

    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    elif text.count(":") == 1:
        host, port = text.split(":")
    else:
        # A hostname, an IPv4 address or a bare IPv6 address (several colons).
        host, port = text, ""

    if not host:
        raise ValueError(f"missing host in {text!r}")

    if port:
        if not port.isdigit():
            raise ValueError(f"invalid port: {port!r}")
        port_number = int(port)
    else:
        port_number = default_port

    if not 1 <= port_number <= 65535:
        raise ValueError(f"port out of range: {port_number}")

    return Target(host=host, port=port_number, scheme=scheme)
