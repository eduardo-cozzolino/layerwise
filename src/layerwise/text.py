"""Make text ASCII-only, so the output reads the same on any console and in any language."""

from __future__ import annotations

import unicodedata


def to_ascii(text: str) -> str:
    """Drop accents ("Certificació" -> "Certificacio"), escape whatever is left (\\u4e2d)."""
    decomposed = unicodedata.normalize("NFKD", text)
    stripped = "".join(char for char in decomposed if not unicodedata.combining(char))
    return stripped.encode("ascii", "backslashreplace").decode("ascii")


def ascii_host(host: str) -> str:
    """The name as DNS sees it: internationalized names in punycode (xn--...)."""
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        # Not a valid name for IDNA (e.g. a label over 63 characters): escape instead.
        return host.encode("ascii", "backslashreplace").decode("ascii")
