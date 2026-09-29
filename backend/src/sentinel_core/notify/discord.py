"""Discord notifications for the responder (best effort).

A notification is information, never a dependency: `send` never raises and never blocks a decision
for long (short timeout, no retry). The webhook URL is a secret (anyone holding it can post in the
channel): it is validated, kept out of `repr()` and out of every log line, and mentions are
disabled so that a crafted value cannot ping anyone.
"""

import logging
from collections.abc import Sequence
from urllib.parse import urlsplit

import httpx

from sentinel_core.terminal import sanitize

logger = logging.getLogger("sentinel.notify")

WEBHOOK_HOSTS = frozenset(
    {"discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"}
)
WEBHOOK_PATH_PREFIX = "/api/webhooks/"
MAX_CONTENT = 2000  # Discord's limit for a message
MAX_LINES = 10
TIMEOUT_SECONDS = 5.0
FIELD_MAX = 120


def validate_webhook_url(url: str) -> str:
    """The URL if it is a Discord webhook, else ValueError (without echoing the secret)."""
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or parts.hostname not in WEBHOOK_HOSTS
        or parts.port not in (None, 443)
        or parts.username
        or parts.password
        or not parts.path.startswith(WEBHOOK_PATH_PREFIX)
        or len(parts.path) <= len(WEBHOOK_PATH_PREFIX)
    ):
        raise ValueError(
            "not a Discord webhook URL (https://discord.com/api/webhooks/<id>/<token>)"
        )
    return url


def _text(value: object) -> str:
    return sanitize(str(value))[:FIELD_MAX]


def duration(seconds: int) -> str:
    if seconds % 86_400 == 0:
        return f"{seconds // 86_400} d"
    if seconds % 3_600 == 0:
        return f"{seconds // 3_600} h"
    if seconds % 60 == 0:
        return f"{seconds // 60} min"
    return f"{seconds} s"


def block_line(
    *, address: str, mode: str, rule_id: str, match_count: int, severity: int, ttl_seconds: int
) -> str:
    head = "🚫 **BLOCKED**" if mode == "enforce" else "🟡 would block (dry run)"
    return (
        f"{head} `{_text(address)}` for {duration(ttl_seconds)} — `{_text(rule_id)}`, "
        f"{match_count} event(s), severity {severity}"
    )


def release_line(*, address: str) -> str:
    return f"✅ **RELEASED** `{_text(address)}` (block expired)"


def silent_line(*, name: str, last_seen: str, minutes: int) -> str:
    return (
        f"🔇 **SILENT** agent `{_text(name)}` has not reported for {minutes} min "
        f"(last seen {_text(last_seen)} UTC): detection is blind on that host"
    )


def back_line(*, name: str) -> str:
    return f"🔔 agent `{_text(name)}` is reporting again"


def compose(lines: Sequence[str]) -> str:
    """One message for a batch of lines: capped, so a burst never floods the channel."""
    shown = list(lines[:MAX_LINES])
    if len(lines) > MAX_LINES:
        shown.append(f"… and {len(lines) - MAX_LINES} more")
    return "\n".join(shown)[:MAX_CONTENT]


class DiscordNotifier:
    def __init__(self, url: str, http: httpx.AsyncClient | None = None) -> None:
        self._url = validate_webhook_url(url)
        # httpx logs "HTTP Request: POST <url>" at INFO, and this URL carries the secret token.
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        self._http = http or httpx.AsyncClient(timeout=TIMEOUT_SECONDS, follow_redirects=False)

    def __repr__(self) -> str:
        return "DiscordNotifier(url=<hidden>)"

    async def send(self, lines: Sequence[str]) -> bool:
        """Post the lines as one message. True if Discord accepted it; never raises."""
        if not lines:
            return True
        try:
            response = await self._http.post(
                self._url,
                json={
                    "username": "SentinelLite",
                    "content": compose(lines),
                    "allowed_mentions": {"parse": []},
                },
            )
        except httpx.HTTPError as exc:
            # The exception text can contain the request URL, which holds the secret token.
            logger.warning("Discord notification failed (%s)", type(exc).__name__)
            return False
        if response.status_code >= 300:
            logger.warning("Discord refused the notification (HTTP %d)", response.status_code)
            return False
        return True

    async def aclose(self) -> None:
        await self._http.aclose()
