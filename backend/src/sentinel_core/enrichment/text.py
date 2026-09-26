"""Cleaning of text that comes from outside (databases, third-party APIs)."""

import unicodedata
from typing import Any

MAX_TEXT = 100


def clean_text(value: Any) -> str | None:
    """`value` as a short single-line string without control characters, or None if it is not text
    or nothing is left. It ends up in alerts and, later, in a web page."""
    if not isinstance(value, str):
        return None
    cleaned = "".join(c for c in value if unicodedata.category(c)[0] != "C").strip()
    return cleaned[:MAX_TEXT] or None
