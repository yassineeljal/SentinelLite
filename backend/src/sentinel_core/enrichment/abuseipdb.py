"""AbuseIPDB client: how badly reported is a public address?

Unlike GeoIP, this SENDS the address to a third party (abuseipdb.com), so it is opt-in, only ever
sent public addresses, and every failure mode is handled here so that callers can simply leave the
alert without a reputation. The API key travels in a header, is held only by this object, and never
appears in a URL, an exception message or a repr. The answer is untrusted: it is parsed strictly
and its text is cleaned and bounded.
"""

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import httpx
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    ValidationError,
    field_validator,
)

from sentinel_core.enrichment.text import clean_text

BASE_URL = "https://api.abuseipdb.com"
CHECK_PATH = "/api/v2/check"
DEFAULT_TIMEOUT_SECONDS = 5.0


class ReputationError(Exception):
    """Base of everything that can go wrong; none of these messages contains the key."""


class QuotaExceeded(ReputationError):
    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(f"AbuseIPDB quota exceeded, retry in {retry_after_seconds}s")
        self.retry_after_seconds = retry_after_seconds


class AuthRejected(ReputationError):
    """The key was refused (401/403): revoked, mistyped or not activated."""


class BadRequest(ReputationError):
    """The address was refused (locally or by the API)."""


class Unavailable(ReputationError):
    """Network failure, server error or an answer that cannot be trusted."""


class Reputation(BaseModel):
    """What the provider says about an address. Stored on the alert and cached."""

    model_config = ConfigDict(frozen=True)

    source: Literal["abuseipdb"] = "abuseipdb"
    score: int = Field(ge=0, le=100, description="AbuseIPDB abuse confidence, 0-100")
    total_reports: int = Field(ge=0)
    distinct_reporters: int = Field(ge=0)
    last_reported_at: AwareDatetime | None = None
    usage_type: str | None = None
    isp: str | None = None
    is_tor: bool = False
    is_whitelisted: bool = False
    checked_at: AwareDatetime = Field(description="When the provider was asked (cache age)")

    @field_validator("usage_type", "isp", mode="before")
    @classmethod
    def _clean(cls, value: Any) -> str | None:
        return clean_text(value)


class _Answer(BaseModel):
    """The part of the provider's answer that is used; anything odd is a validation error."""

    model_config = ConfigDict(extra="ignore")

    abuseConfidenceScore: StrictInt = Field(ge=0, le=100)
    totalReports: StrictInt = Field(ge=0)
    numDistinctUsers: StrictInt = Field(ge=0)
    lastReportedAt: AwareDatetime | None = None
    usageType: Any = None
    isp: Any = None
    isTor: bool | None = False
    isWhitelisted: bool | None = False


@dataclass(frozen=True)
class CheckResult:
    reputation: Reputation
    remaining: int | None  # requests left in the current period, from the response headers
    reset_at: datetime | None  # when the quota period ends


def _now() -> datetime:
    return datetime.now(UTC)


def seconds_until_midnight(now: datetime) -> int:
    midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(1, int((midnight - now).total_seconds()))


def _int_header(response: httpx.Response, name: str) -> int | None:
    value = response.headers.get(name)
    if value is None or not value.isdigit():
        return None
    return int(value)


class AbuseIpDbClient:
    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = BASE_URL,
        max_age_days: int = 90,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        http: httpx.AsyncClient | None = None,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        if not api_key:
            raise ValueError("an AbuseIPDB key is required")
        if not base_url.startswith("https://"):
            raise ValueError("the AbuseIPDB URL must be https (the key is sent in a header)")
        self._key = api_key
        self._url = base_url.rstrip("/") + CHECK_PATH
        self._max_age_days = max_age_days
        self._clock = clock
        self._owns_http = http is None
        # No redirects: the key must never follow a redirect to another host.
        self._http = http or httpx.AsyncClient(timeout=timeout, follow_redirects=False)

    def __repr__(self) -> str:
        return "AbuseIpDbClient(<key hidden>)"

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def check(self, ip: str) -> CheckResult:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            raise BadRequest("not an IP address") from None
        if not address.is_global or address.is_multicast:
            raise BadRequest("not a public address: never sent to a third party")

        try:
            response = await self._http.get(
                self._url,
                params={"ipAddress": str(address), "maxAgeInDays": str(self._max_age_days)},
                headers={"Key": self._key, "Accept": "application/json"},
            )
        except httpx.HTTPError as exc:  # timeouts, refused connections, TLS errors...
            raise Unavailable(f"request failed: {type(exc).__name__}") from None

        status = response.status_code
        if status == 429:
            raise QuotaExceeded(self._retry_after(response))
        if status in (401, 403):
            raise AuthRejected(f"the key was refused (HTTP {status})")
        if status == 422:
            raise BadRequest("the address was refused by the API")
        if status != 200:
            raise Unavailable(f"unexpected HTTP status {status}")

        reset = _int_header(response, "X-RateLimit-Reset")
        return CheckResult(
            reputation=self._parse(response),
            remaining=_int_header(response, "X-RateLimit-Remaining"),
            reset_at=datetime.fromtimestamp(reset, UTC) if reset else None,
        )

    def _retry_after(self, response: httpx.Response) -> int:
        now = self._clock()
        retry = _int_header(response, "Retry-After")
        if retry is not None:
            return max(1, retry)
        reset = _int_header(response, "X-RateLimit-Reset")
        if reset is not None and reset > now.timestamp():
            return int(reset - now.timestamp())
        return seconds_until_midnight(now)  # the daily quota resets at 00:00 UTC

    def _parse(self, response: httpx.Response) -> Reputation:
        try:
            body = response.json()
            data = body["data"]
            answer = _Answer.model_validate(data)
            return Reputation(
                score=answer.abuseConfidenceScore,
                total_reports=answer.totalReports,
                distinct_reporters=answer.numDistinctUsers,
                last_reported_at=answer.lastReportedAt,
                usage_type=answer.usageType,
                isp=answer.isp,
                is_tor=bool(answer.isTor),
                is_whitelisted=bool(answer.isWhitelisted),
                checked_at=self._clock(),
            )
        except (ValueError, KeyError, TypeError, ValidationError):
            raise Unavailable("the answer is not what the API documents") from None
