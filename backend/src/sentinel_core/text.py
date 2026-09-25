"""Neutralising text that PostgreSQL or UTF-8 cannot represent.

Log lines are attacker-controlled. Two kinds of content make a database write fail
*deterministically*: NUL bytes (rejected by PostgreSQL `text` and `jsonb`) and lone UTF-16
surrogates (not encodable as UTF-8). A line like that would make every retry of its batch fail
and block the lines of every other agent behind it, so it is neutralised at the boundary.
"""


def storable(text: str) -> str:
    """`text` with NUL bytes and lone surrogates replaced by visible escapes (\\x00, \\ud800)."""
    return text.replace("\x00", "\\x00").encode("utf-8", "backslashreplace").decode("utf-8")
