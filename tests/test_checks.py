"""Checks against real sockets on 127.0.0.1, so the tests need no internet access."""

import http.client
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from layerwise import checks
from layerwise.models import Status


@pytest.fixture
def listening_port():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen()
    yield server.getsockname()[1]
    server.close()


@pytest.fixture
def closed_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def http_server(status_code, reason=None, headers=None):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status_code, reason)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_dns_skips_ip_addresses():
    result, addresses = checks.check_dns("192.0.2.10")
    assert result.status is Status.SKIP
    assert addresses == [(socket.AF_INET, "192.0.2.10")]


def test_dns_skips_ipv6_addresses():
    _, addresses = checks.check_dns("2001:db8::1")
    assert addresses == [(socket.AF_INET6, "2001:db8::1")]


def test_dns_resolves_localhost():
    result, addresses = checks.check_dns("localhost")
    assert result.status is Status.OK
    assert addresses


def test_dns_failure_has_a_hint(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    result, addresses = checks.check_dns("does-not-exist.invalid")
    assert result.status is Status.FAIL
    assert addresses == []
    assert "nslookup" in result.hint


def test_tcp_connects(listening_port):
    result = checks.check_tcp("127.0.0.1", socket.AF_INET, listening_port, timeout=3)
    assert result.status in (Status.OK, Status.WARN)
    assert result.name == "TCP IPv4"


def test_tcp_refused(closed_port):
    result = checks.check_tcp("127.0.0.1", socket.AF_INET, closed_port, timeout=3)
    assert result.status is Status.FAIL
    assert "refused" in result.summary
    assert "nothing is listening" in result.hint


def test_tcp_timeout(monkeypatch):
    def timeout(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(socket, "create_connection", timeout)
    result = checks.check_tcp("192.0.2.10", socket.AF_INET, 443, timeout=1)
    assert result.status is Status.FAIL
    assert "dropped silently" in result.hint


def test_tcp_unreachable(monkeypatch):
    def unreachable(*args, **kwargs):
        raise OSError(next(iter(checks.UNREACHABLE_ERRNOS)), "Network is unreachable")

    monkeypatch.setattr(socket, "create_connection", unreachable)
    result = checks.check_tcp("2001:db8::1", socket.AF_INET6, 443, timeout=1)
    assert result.status is Status.FAIL
    assert result.summary == "no route to 2001:db8::1"


CERT_EXPIRY = "Jan  1 00:00:00 2030 GMT"
CERT = {
    "notAfter": CERT_EXPIRY,
    "issuer": ((("countryName", "US"),), (("organizationName", "Let's Encrypt"),)),
}


def test_certificate_valid():
    now = ssl.cert_time_to_seconds(CERT_EXPIRY) - 90 * 86400
    result = checks.summarize_certificate("TLSv1.3", CERT, now)
    assert result.status is Status.OK
    assert result.details["days_left"] == 90
    assert result.details["issuer"] == "Let's Encrypt"


def test_certificate_expiring_soon():
    now = ssl.cert_time_to_seconds(CERT_EXPIRY) - 5 * 86400
    result = checks.summarize_certificate("TLSv1.3", CERT, now)
    assert result.status is Status.WARN
    assert "renew" in result.hint


def test_tls_on_a_plain_tcp_port_fails(listening_port):
    # The listener accepts but never answers the ClientHello, so the handshake times out.
    result = checks.check_tls("localhost", "127.0.0.1", listening_port, timeout=0.5)
    assert result.status is Status.FAIL


# Windows error texts as an Italian system prints them: translated, with accents.
IT_RESET = "È stata forzata la chiusura di una connessione esistente dall'host remoto"
IT_TIMEOUT = "Il tentativo di connessione non è riuscito: l'host non ha risposto"


def _raise(exc):
    def raiser(*args, **kwargs):
        raise exc

    return raiser


def _cert_error(code, message):
    exc = ssl.SSLCertVerificationError(1, message)
    exc.verify_code, exc.verify_message = code, message
    return exc


def _ssl_error():
    exc = ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] numero di versione è errato")
    exc.reason = "WRONG_VERSION_NUMBER"
    return exc


def _dns(monkeypatch, host, exc):
    monkeypatch.setattr(socket, "getaddrinfo", _raise(exc))
    return checks.check_dns(host)[0]


def _tcp(monkeypatch, exc):
    monkeypatch.setattr(socket, "create_connection", _raise(exc))
    return checks.check_tcp("192.0.2.10", socket.AF_INET, 443, timeout=1)


def _tls(monkeypatch, exc):
    monkeypatch.setattr(socket, "create_connection", _raise(exc))
    return checks.check_tls("example.com", "192.0.2.10", 443, timeout=1)


def _http_error(monkeypatch):
    monkeypatch.setattr(
        http.client.HTTPConnection, "request", _raise(ConnectionResetError(10054, IT_RESET))
    )
    return checks.check_http("example.com", "192.0.2.10", 80, timeout=1, use_tls=False)


def _http_latin1(monkeypatch):
    # A server sending a French reason phrase and an accented Location (latin-1 on the wire).
    server = http_server(301, reason="Déplacé", headers={"Location": "/café"})
    try:
        port = server.server_address[1]
        return checks.check_http("127.0.0.1", "127.0.0.1", port, 3, use_tls=False)
    finally:
        server.shutdown()
        server.server_close()


def _accented_issuer(monkeypatch):
    cert = {**CERT, "issuer": ((("organizationName", "Agència Catalana de Certificació"),),)}
    return checks.summarize_certificate("TLSv1.3", cert, ssl.cert_time_to_seconds(CERT_EXPIRY))


SCENARIOS = {
    # id: (produce the result, expected in summary, original text expected in details)
    "dns-noname": (
        lambda mp: _dns(
            mp, "example.com", socket.gaierror(socket.EAI_NONAME, "Host sconosciuto è")
        ),
        "name not found",
        "Host sconosciuto è",
    ),
    "dns-unknown-code": (
        lambda mp: _dns(mp, "example.com", socket.gaierror(99999, "Errore è")),
        "resolver error 99999",
        "Errore è",
    ),
    "dns-idn": (
        lambda mp: _dns(mp, "bücher.example", socket.gaierror(socket.EAI_NONAME, "è")),
        "xn--bcher-kva.example",
        "è",
    ),
    "tcp-refused": (
        lambda mp: _tcp(mp, ConnectionRefusedError(10061, "Rifiuto persistente è")),
        "refused",
        "Rifiuto persistente è",
    ),
    "tcp-timeout": (lambda mp: _tcp(mp, TimeoutError(10060, IT_TIMEOUT)), "no answer", IT_TIMEOUT),
    "tcp-unreachable": (
        lambda mp: _tcp(mp, OSError(10065, "Host non raggiungibile è")),
        "no route",
        "Host non raggiungibile è",
    ),
    "tcp-reset": (
        lambda mp: _tcp(mp, ConnectionResetError(10054, IT_RESET)),
        "ConnectionResetError",
        IT_RESET,
    ),
    "tls-expired": (
        lambda mp: _tls(mp, _cert_error(10, "certificate has expired")),
        "certificate has expired",
        "certificate has expired",
    ),
    "tls-untrusted-root": (
        lambda mp: _tls(mp, _cert_error(19, "self-signed certificate in certificate chain")),
        "not trusted",
        "self-signed certificate in certificate chain",
    ),
    "tls-issuer-not-found": (
        lambda mp: _tls(mp, _cert_error(20, "unable to get local issuer certificate")),
        "issuer certificate not found",
        "unable to get local issuer certificate",
    ),
    "tls-unmapped-code": (
        lambda mp: _tls(mp, _cert_error(99, "codice è strano")),
        "verify code 99: codice e strano",
        "codice è strano",
    ),
    "tls-handshake": (lambda mp: _tls(mp, _ssl_error()), "WRONG_VERSION_NUMBER", None),
    "tls-reset": (
        lambda mp: _tls(mp, ConnectionResetError(10054, IT_RESET)),
        "ConnectionResetError",
        IT_RESET,
    ),
    "http-reset": (_http_error, "ConnectionResetError", IT_RESET),
    "http-latin1": (_http_latin1, "301 Deplace -> /cafe", "/café"),
    "cert-accented-issuer": (
        _accented_issuer,
        "Agencia Catalana de Certificacio",
        "Agència Catalana de Certificació",
    ),
}


@pytest.mark.parametrize("scenario", SCENARIOS.values(), ids=SCENARIOS.keys())
def test_messages_are_ascii(monkeypatch, scenario):
    produce, expected_summary, original = scenario
    result = produce(monkeypatch)
    assert result.summary.isascii(), result.summary
    assert result.hint is None or result.hint.isascii(), result.hint
    assert expected_summary in result.summary
    if original is not None:
        assert any(original in str(value) for value in result.details.values())


def test_missing_root_hint_points_to_the_certificate_store(monkeypatch):
    result = _tls(monkeypatch, _cert_error(20, "unable to get local issuer certificate"))
    assert result.status is Status.FAIL
    assert "missing from the local certificate store" in result.hint
    assert "Invoke-WebRequest https://example.com and retry" in result.hint
    assert "openssl s_client -connect 192.0.2.10:443" in result.hint


def test_other_certificate_errors_keep_the_generic_hint(monkeypatch):
    result = _tls(monkeypatch, _cert_error(10, "certificate has expired"))
    assert "certificate store" not in result.hint
    assert "expired, self-signed" in result.hint


@pytest.mark.parametrize(
    ("code", "expected"),
    [(200, Status.OK), (301, Status.OK), (404, Status.WARN), (503, Status.FAIL)],
)
def test_http_status_codes(code, expected):
    server = http_server(code)
    try:
        port = server.server_address[1]
        result = checks.check_http("127.0.0.1", "127.0.0.1", port, timeout=3, use_tls=False)
    finally:
        server.shutdown()
        server.server_close()
    assert result.status is expected
    assert result.details["status"] == code


def test_http_sends_the_name_and_path_to_the_address():
    # The name does not resolve to 127.0.0.1: only the address decides where the request goes.
    received = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            received["hosts"] = self.headers.get_all("Host")
            received["path"] = self.path
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        result = checks.check_http(
            "www.example.com", "127.0.0.1", port, timeout=3, use_tls=False, path="/login?x=1"
        )
    finally:
        server.shutdown()
        server.server_close()
    assert result.status is Status.OK
    assert received == {"hosts": [f"www.example.com:{port}"], "path": "/login?x=1"}


@pytest.mark.parametrize(
    ("host", "port", "use_tls", "expected"),
    [
        ("example.com", 443, True, "example.com"),
        ("example.com", 80, False, "example.com"),
        ("example.com", 8443, True, "example.com:8443"),
        ("example.com", 443, False, "example.com:443"),
        ("bücher.example", 443, True, "xn--bcher-kva.example"),
        ("2001:db8::1", 8080, False, "[2001:db8::1]:8080"),
    ],
)
def test_host_header(host, port, use_tls, expected):
    assert checks._host_header(host, port, use_tls) == expected


def test_https_connects_to_the_address_but_verifies_the_name(monkeypatch):
    connection = checks._NamedHTTPSConnection("192.0.2.10", 443, "example.com", timeout=1)
    seen = {}

    def create(address, *args, **kwargs):
        seen["address"] = address
        return socket.socket()

    def wrap(sock, server_hostname):
        seen["server_hostname"] = server_hostname
        return sock

    monkeypatch.setattr(connection, "_create_connection", create)
    monkeypatch.setattr(connection._tls_context, "wrap_socket", wrap)
    connection.connect()
    connection.close()
    assert seen == {"address": ("192.0.2.10", 443), "server_hostname": "example.com"}


def test_slow_tcp_is_tagged(monkeypatch, listening_port):
    # The report tells "slow" apart from a downgraded failure by this reason, not by the text.
    monkeypatch.setattr(checks, "SLOW_TCP_MS", -1)
    result = checks.check_tcp("127.0.0.1", socket.AF_INET, listening_port, timeout=3)
    assert result.status is Status.WARN
    assert result.details["reason"] == "slow"
