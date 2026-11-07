"""Make untrusted text (file names from a stick, names from another PC) safe to print."""

from __future__ import annotations

import unicodedata


def clean_text(s: str, limit: int = 200) -> str:
    """No control characters, no terminal escape sequences, no invisible/bidi-override
    characters that could disguise a name. Each one becomes '?'."""
    return "".join(ch if unicodedata.category(ch)[0] != "C" else "?" for ch in s)[:limit]


def safe_print(msg: str) -> None:
    """print() for lines that may contain names from a stick or another PC."""
    print(clean_text(str(msg), 100_000))
