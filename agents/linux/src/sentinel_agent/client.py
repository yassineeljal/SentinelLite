"""HTTP client for `POST /v1/ingest`, standard library only.

`send` never raises: every outcome is a value the shipper can act on. The mapping follows
docs/INGESTION_API.md (202 accepted, 401 credentials, 413 too large, 422 rejected, 429 queue
full, 5xx / network unavailable).
"""

import http.client
import json
import logging
import ssl
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("sentinel_agent.client")

USER_AGENT = "sentinel-agent/0.1"
DEFAULT_RETRY_AFTER = 5.0
MAX_RETRY_AFTER = 300.0
MAX_DETAIL = 300


@dataclass(frozen=True)
class Accepted:
    count: int


@dataclass(frozen=True)
class RetryAfter:  # 429: the server's queue is full
    seconds: float


@dataclass(frozen=True)
class TooLarge:  # 413
    detail: str = ""


@dataclass(frozen=True)
class Rejected:  # 422 and other 4xx: this exact payload will never be accepted
    detail: str = ""


@dataclass(frozen=True)
class Unauthorized:  # 401: the key is unknown or revoked
    pass


@dataclass(frozen=True)
class Unavailable:  # 5xx, network error, timeout: try again later
    reason: str = ""


Result = Accepted | RetryAfter | TooLarge | Rejected | Unauthorized | Unavailable


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would send the Authorization header to another host: refuse to follow."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def _retry_after(header: str | None) -> float:
    try:
        seconds = float(header) if header is not None else DEFAULT_RETRY_AFTER
    except ValueError:
        seconds = DEFAULT_RETRY_AFTER
    return min(max(seconds, 1.0), MAX_RETRY_AFTER)


class IngestClient:
    def __init__(
        self, base_url: str, key: str, ca_file: Path | None = None, timeout: float = 10.0
    ) -> None:
        self._url = base_url.rstrip("/") + "/v1/ingest"
        self._key = key
        self._timeout = timeout
        handlers: list[urllib.request.BaseHandler] = [_NoRedirect()]
        if base_url.startswith("https://"):
            context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self._opener = urllib.request.build_opener(*handlers)

    def __repr__(self) -> str:
        return f"IngestClient(url={self._url!r}, key=<hidden>)"

    def send(self, source: str, lines: Sequence[tuple[str, str]]) -> Result:
        body = json.dumps(
            {"source": source, "lines": [{"origin": o, "line": t} for o, t in lines]},
            ensure_ascii=False,
        ).encode()
        request = urllib.request.Request(  # noqa: S310 - scheme validated in the configuration
            self._url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._key}",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                return Accepted(self._accepted(response.read(), len(lines)))
        except urllib.error.HTTPError as exc:
            return self._from_error(exc)
        except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
            return Unavailable(f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}")

    @staticmethod
    def _accepted(payload: bytes, sent: int) -> int:
        try:
            return int(json.loads(payload)["accepted"])
        except (ValueError, KeyError, TypeError):
            return sent  # a 202 is a 202, whatever the body says

    @staticmethod
    def _from_error(exc: urllib.error.HTTPError) -> Result:
        try:
            detail = exc.read(MAX_DETAIL * 4).decode(errors="replace")[:MAX_DETAIL]
        except OSError:
            detail = ""
        status = exc.code
        if status == 401:
            return Unauthorized()
        if status == 413:
            return TooLarge(detail)
        if status == 429:
            return RetryAfter(_retry_after(exc.headers.get("Retry-After")))
        if 400 <= status < 500:
            return Rejected(f"HTTP {status}: {detail}"[:MAX_DETAIL])
        return Unavailable(f"HTTP {status}")
