import pytest

from sentinel_core.terminal import sanitize


def test_plain_text_is_unchanged() -> None:
    assert sanitize("Failed password for root from 203.0.113.7 port 22 ssh2") == (
        "Failed password for root from 203.0.113.7 port 22 ssh2"
    )
    assert sanitize("café 中文") == "café 中文"  # printable unicode stays


@pytest.mark.parametrize(
    ("hostile", "expected"),
    [
        ("\x1b[2K\x1b[1A", "\\x1b[2K\\x1b[1A"),  # cursor / erase sequences (hide evidence)
        ("\x1b]52;c;ZWNobyBoaQ==\x07", "\\x1b]52;c;ZWNobyBoaQ==\\x07"),  # OSC 52 clipboard write
        ("a\rb", "a\\x0db"),  # carriage return overwrites the line start
        ("a\nb\tc", "a\\x0ab\\x09c"),  # newlines/tabs cannot forge extra lines
        ("\x9b31m", "\\x9b31m"),  # 8-bit CSI
        ("\x7f", "\\x7f"),
        ("evil‮gnp.exe", "evil\\u202egnp.exe"),  # bidirectional override
        ("​", "\\u200b"),  # zero-width space
    ],
)
def test_control_and_format_characters_are_made_visible(hostile: str, expected: str) -> None:
    assert sanitize(hostile) == expected


def test_no_control_character_survives() -> None:
    everything = "".join(chr(c) for c in range(0x110000) if not 0xD800 <= c <= 0xDFFF)

    cleaned = sanitize(everything)

    assert all(ch.isprintable() for ch in cleaned)


def test_none_is_shown_as_a_dash() -> None:
    assert sanitize(None) == "-"


def test_an_empty_string_is_shown_as_a_dash_like_none() -> None:
    assert sanitize("") == "-"
