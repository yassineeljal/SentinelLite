"""Safe display of attacker-controlled text on an analyst's terminal.

Log lines, user names and host names come from the monitored machines, and so from whoever
attacks them. Printed raw, a line can carry escape sequences that erase or rewrite evidence
already shown, forge extra lines, spoof the window title or write to the clipboard (OSC 52).
Every character that is not plainly printable is replaced by a visible escape.
"""


def sanitize(text: str | None) -> str:
    """`text` with control, format (e.g. bidi override) and unassigned characters escaped.

    None and the empty string are shown as "-" so that table columns never look shifted."""
    if not text:
        return "-"
    return "".join(ch if ch.isprintable() else _escape(ord(ch)) for ch in text)


def _escape(codepoint: int) -> str:
    if codepoint <= 0xFF:
        return f"\\x{codepoint:02x}"
    if codepoint <= 0xFFFF:
        return f"\\u{codepoint:04x}"
    return f"\\U{codepoint:08x}"
