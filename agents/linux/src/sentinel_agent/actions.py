"""HTTP client for the action channel: `GET /v1/agents/me/actions` and `POST .../{id}/ack`.

Like the ingestion client it never raises: each outcome is a value the caller acts on. The agent
always initiates the connection (pull), so nothing listens on the monitored machine.
"""

import http.client
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sentinel_agent.client import USER_AGENT, Unauthorized, Unavailable, _NoRedirect

MAX_BODY = 1_000_000


@dataclass(frozen=True)
class Action:
    id: int
    kind: str
    ip: str
    expires_at: datetime


@dataclass(frozen=True)
class Fetched:
    actions: list[Action]


@dataclass(frozen=True)
class Acknowledged:
    pass


@dataclass(frozen=True)
class Gone:  # 404: unknown, not ours, or already answered: never retry
    pass


FetchResult = Fetched | Unauthorized | Unavailable
AckResult = Acknowledged | Gone | Unauthorized | Unavailable


class ActionClient:
    def __init__(
        self, base_url: str, key: str, ca_file: Path | None = None, timeout: float = 10.0
    ) -> None:
        self._base = base_url.rstrip("/") + "/v1/agents/me/actions"
        self._key = key
        self._timeout = timeout
        handlers: list[urllib.request.BaseHandler] = [_NoRedirect()]
        if base_url.startswith("https://"):
            context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self._opener = urllib.request.build_opener(*handlers)

    def __repr__(self) -> str:
        return f"ActionClient(url={self._base!r}, key=<hidden>)"

    def _request(self, method: str, url: str, body: object | None) -> tuple[int, bytes]:
        request = urllib.request.Request(  # noqa: S310 - scheme validated in the configuration
            url,
            data=None if body is None else json.dumps(body).encode(),
            method=method,
            headers={
                "Authorization": f"Bearer {self._key}",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                return response.status, response.read(MAX_BODY)
        except urllib.error.HTTPError as exc:
            return exc.code, b""

    def fetch(self) -> FetchResult:
        try:
            status, payload = self._request("GET", self._base, None)
        except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
            return Unavailable(f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}")
        if status == 401:
            return Unauthorized()
        if status != 200:
            return Unavailable(f"HTTP {status}")
        try:
            return Fetched(_parse(payload))
        except (ValueError, KeyError, TypeError) as exc:
            # A malformed answer is never acted upon.
            return Unavailable(f"unreadable answer ({type(exc).__name__})")

    def acknowledge(self, action_id: int, status: str, detail: str = "") -> AckResult:
        try:
            code, _ = self._request(
                "POST", f"{self._base}/{action_id}/ack", {"status": status, "detail": detail[:500]}
            )
        except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
            return Unavailable(f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}")
        if code == 204:
            return Acknowledged()
        if code == 401:
            return Unauthorized()
        if code in (404, 422):
            return Gone()
        return Unavailable(f"HTTP {code}")


def _parse(payload: bytes) -> list[Action]:
    data = json.loads(payload)
    actions: list[Action] = []
    for item in data["actions"]:
        if item["kind"] not in ("block", "unblock"):
            raise ValueError("unknown action kind")
        actions.append(
            Action(
                id=int(item["id"]),
                kind=str(item["kind"]),
                ip=str(item["ip"]),
                expires_at=datetime.fromisoformat(str(item["expires_at"])),
            )
        )
    return actions
