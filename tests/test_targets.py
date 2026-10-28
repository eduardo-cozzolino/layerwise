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
        ("http://example.com/some/path", Target("example.com", 80, "http")),
        ("https://example.com:8443/", Target("example.com", 8443, "https")),
        ("  example.com  ", Target("example.com", 443)),
    ],
)
def test_parse_target(text, expected):
    assert parse_target(text) == expected


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
