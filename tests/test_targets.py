import pytest

from layerwise.targets import Target, parse_target


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("example.com", Target("example.com", 443)),
        ("example.com:22", Target("example.com", 22)),
        ("10.0.0.1", Target("10.0.0.1", 443)),
        ("10.0.0.1:8080", Target("10.0.0.1", 8080)),
        ("2001:db8::1", Target("2001:db8::1", 443)),
        ("[2001:db8::1]:53", Target("2001:db8::1", 53)),
        ("[2001:db8::1]", Target("2001:db8::1", 443)),
        ("http://example.com/some/path", Target("example.com", 80, "http", "/some/path")),
        ("https://example.com:8443/", Target("example.com", 8443, "https", "/")),
        ("https://example.com", Target("example.com", 443, "https")),
        ("  example.com  ", Target("example.com", 443)),
    ],
)
def test_parse_target(text, expected):
    assert parse_target(text) == expected


@pytest.mark.parametrize(
    ("text", "path"),
    [
        ("https://example.com/login?next=/home", "/login?next=/home"),
        ("https://example.com?q=1", "/?q=1"),
        ("https://example.com/docs#install", "/docs"),
        ("https://[2001:db8::1]:8443/status", "/status"),
        ("example.com:8080", None),
    ],
)
def test_url_path_is_kept(text, path):
    assert parse_target(text).path == path


def test_default_port_is_used_when_missing():
    assert parse_target("example.com", default_port=25).port == 25


@pytest.mark.parametrize("text", ["example.com:0", "example.com:70000", "example.com:ssh", ":80"])
def test_invalid_targets(text):
    with pytest.raises(ValueError):
        parse_target(text)


def test_unsupported_scheme():
    with pytest.raises(ValueError):
        parse_target("ftp://example.com")


def test_str_brackets_ipv6():
    assert str(Target("2001:db8::1", 443)) == "[2001:db8::1]:443"
    assert str(Target("example.com", 80)) == "example.com:80"
