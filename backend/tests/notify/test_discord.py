import json
import logging

import httpx
import pytest

from sentinel_core.notify.discord import (
    MAX_CONTENT,
    MAX_LINES,
    DiscordNotifier,
    block_line,
    compose,
    duration,
    release_line,
    validate_webhook_url,
)

URL = "https://discord.com/api/webhooks/123456789/SECRET-token_abc"


@pytest.mark.parametrize(
    "url",
    [URL, "https://discordapp.com/api/webhooks/1/x", "https://ptb.discord.com/api/webhooks/1/x"],
)
def test_discord_webhook_urls_are_accepted(url: str) -> None:
    assert validate_webhook_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://discord.com/api/webhooks/1/x",  # plaintext: the token would travel in clear
        "https://evil.example/api/webhooks/1/x",
        "https://discord.com.evil.example/api/webhooks/1/x",
        "https://discord.com@evil.example/api/webhooks/1/x",
        "https://user:pw@discord.com/api/webhooks/1/x",
        "https://discord.com:8443/api/webhooks/1/x",
        "https://discord.com/other/path",
        "https://discord.com/api/webhooks/",
        "https://127.0.0.1/api/webhooks/1/x",
    ],
)
def test_anything_else_is_refused_without_echoing_it(url: str) -> None:
    with pytest.raises(ValueError, match="not a Discord webhook") as caught:
        validate_webhook_url(url)
    with pytest.raises(ValueError) as reference:
        validate_webhook_url("")
    assert str(caught.value) == str(reference.value)  # the same words whatever was passed in


def test_messages_read_well_and_state_the_mode() -> None:
    kwargs = {
        "address": "45.83.64.10",
        "rule_id": "ssh-bruteforce",
        "match_count": 9,
        "severity": 60,
    }
    enforce = block_line(mode="enforce", ttl_seconds=3600, **kwargs)  # type: ignore[arg-type]
    dry = block_line(mode="dry_run", ttl_seconds=300, **kwargs)  # type: ignore[arg-type]

    assert "BLOCKED" in enforce and "`45.83.64.10`" in enforce and "for 1 h" in enforce
    assert "would block" in dry and "BLOCKED" not in dry and "for 5 min" in dry
    assert "RELEASED" in release_line(address="45.83.64.10")


@pytest.mark.parametrize(
    ("seconds", "text"),
    [(45, "45 s"), (300, "5 min"), (3600, "1 h"), (86400, "1 d"), (5400, "90 min")],
)
def test_durations(seconds: int, text: str) -> None:
    assert duration(seconds) == text


def test_untrusted_text_is_neutralised_and_cut() -> None:
    line = block_line(
        address="1.2.3.4\x1b[31m\n@everyone",
        mode="enforce",
        rule_id="r" * 500,
        match_count=1,
        severity=1,
        ttl_seconds=60,
    )

    assert "\x1b" not in line and "\n" not in line
    assert len(line) < 400


def test_a_burst_is_capped_to_one_short_message() -> None:
    lines = [f"line {i}" for i in range(MAX_LINES + 5)]

    message = compose(lines)

    assert message.count("\n") == MAX_LINES  # ten lines plus the "... and 5 more" line
    assert message.endswith("… and 5 more")
    assert len(compose(["x" * 5000])) == MAX_CONTENT


def notifier(handler: httpx.MockTransport) -> DiscordNotifier:
    return DiscordNotifier(URL, httpx.AsyncClient(transport=handler))


async def test_a_message_is_posted_as_json_without_mentions() -> None:
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(204)

    assert await notifier(httpx.MockTransport(handle)).send(["one", "two"]) is True

    (request,) = seen
    assert str(request.url) == URL
    body = json.loads(request.content)
    assert body["content"] == "one\ntwo"
    assert body["allowed_mentions"] == {"parse": []}


async def test_nothing_to_say_sends_nothing() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request expected")

    assert await notifier(httpx.MockTransport(handle)).send([]) is True


@pytest.mark.parametrize("status", [400, 404, 429, 500])
async def test_a_refusal_is_reported_not_raised(
    status: int, caplog: pytest.LogCaptureFixture
) -> None:
    n = notifier(httpx.MockTransport(lambda r: httpx.Response(status)))

    with caplog.at_level(logging.WARNING):
        assert await n.send(["x"]) is False

    assert f"HTTP {status}" in caplog.text
    assert "SECRET" not in caplog.text


async def test_a_network_failure_never_raises_and_never_leaks_the_token(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach {request.url}", request=request)

    with caplog.at_level(logging.DEBUG):
        assert await notifier(httpx.MockTransport(boom)).send(["x"]) is False

    assert "ConnectError" in caplog.text
    assert "SECRET" not in caplog.text


def test_the_token_is_hidden_from_repr() -> None:
    assert "SECRET" not in repr(DiscordNotifier(URL))


def test_httpx_request_logging_is_silenced_because_it_prints_the_url() -> None:
    logging.getLogger("httpx").setLevel(logging.INFO)

    DiscordNotifier(URL)

    assert logging.getLogger("httpx").level == logging.WARNING
