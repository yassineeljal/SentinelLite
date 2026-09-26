from datetime import UTC, datetime

import httpx
import pytest

from sentinel_core.enrichment.abuseipdb import (
    AbuseIpDbClient,
    AuthRejected,
    BadRequest,
    QuotaExceeded,
    Unavailable,
)

KEY = "k" * 80
PAYLOAD = {
    "data": {
        "ipAddress": "185.220.101.1",
        "isPublic": True,
        "isWhitelisted": False,
        "abuseConfidenceScore": 100,
        "countryCode": "DE",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example Hosting",
        "domain": "example.org",
        "isTor": True,
        "totalReports": 1234,
        "numDistinctUsers": 56,
        "lastReportedAt": "2026-09-26T13:36:45+00:00",
    }
}
NOW = datetime(2026, 9, 26, 15, 0, tzinfo=UTC)


def client_for(handler: httpx.MockTransport | None = None, **kwargs: object) -> AbuseIpDbClient:
    transport = handler or httpx.MockTransport(lambda request: httpx.Response(200, json=PAYLOAD))
    return AbuseIpDbClient(
        KEY,
        http=httpx.AsyncClient(transport=transport),
        clock=lambda: NOW,
        **kwargs,  # type: ignore[arg-type]
    )


def replying(
    status: int, body: object = None, headers: dict[str, str] | None = None
) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(status, json=body, headers=headers))


async def test_a_report_is_parsed() -> None:
    result = await client_for().check("185.220.101.1")

    rep = result.reputation
    assert (rep.source, rep.score, rep.total_reports, rep.distinct_reporters) == (
        "abuseipdb",
        100,
        1234,
        56,
    )
    assert rep.is_tor and not rep.is_whitelisted
    assert (rep.usage_type, rep.isp) == ("Data Center/Web Hosting/Transit", "Example Hosting")
    assert rep.last_reported_at == datetime(2026, 9, 26, 13, 36, 45, tzinfo=UTC)
    assert rep.checked_at == NOW


async def test_the_request_carries_the_key_in_a_header_and_never_in_the_url() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=PAYLOAD)

    await client_for(httpx.MockTransport(handler), max_age_days=30).check("185.220.101.1")

    (request,) = seen
    assert request.method == "GET" and request.url.host == "api.abuseipdb.com"
    assert request.url.path == "/api/v2/check"
    assert dict(request.url.params) == {"ipAddress": "185.220.101.1", "maxAgeInDays": "30"}
    assert request.headers["Key"] == KEY and request.headers["Accept"] == "application/json"
    assert KEY not in str(request.url)


async def test_the_quota_headers_are_reported() -> None:
    headers = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1790467200"}

    result = await client_for(replying(200, PAYLOAD, headers)).check("185.220.101.1")

    assert result.remaining == 0
    assert result.reset_at == datetime.fromtimestamp(1790467200, UTC)


async def test_missing_or_odd_quota_headers_are_ignored() -> None:
    headers = {"X-RateLimit-Remaining": "lots", "X-RateLimit-Reset": "-5"}

    result = await client_for(replying(200, PAYLOAD, headers)).check("185.220.101.1")

    assert result.remaining is None and result.reset_at is None


async def test_too_many_requests_says_when_to_come_back() -> None:
    with pytest.raises(QuotaExceeded) as exc:
        await client_for(replying(429, {}, {"Retry-After": "3600"})).check("185.220.101.1")
    assert exc.value.retry_after_seconds == 3600

    reset = {"X-RateLimit-Reset": str(int(NOW.timestamp()) + 120)}
    with pytest.raises(QuotaExceeded) as exc:
        await client_for(replying(429, {}, reset)).check("185.220.101.1")
    assert exc.value.retry_after_seconds == 120

    with pytest.raises(QuotaExceeded) as exc:  # nothing to go by: wait a while, not forever
        await client_for(replying(429, {})).check("185.220.101.1")
    assert 0 < exc.value.retry_after_seconds <= 24 * 3600


@pytest.mark.parametrize("status", [401, 403])
async def test_a_refused_key_is_reported_as_such(status: int) -> None:
    with pytest.raises(AuthRejected):
        await client_for(replying(status, {"errors": [{"detail": "bad key"}]})).check("8.8.8.8")


async def test_a_rejected_address_is_a_bad_request() -> None:
    with pytest.raises(BadRequest):
        await client_for(replying(422, {"errors": []})).check("185.220.101.1")


@pytest.mark.parametrize("status", [500, 502, 503])
async def test_server_errors_mean_unavailable(status: int) -> None:
    with pytest.raises(Unavailable):
        await client_for(replying(status)).check("185.220.101.1")


async def test_network_failures_mean_unavailable() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out", request=request)

    with pytest.raises(Unavailable):
        await client_for(httpx.MockTransport(boom)).check("185.220.101.1")


@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        {},
        {"data": None},
        {"data": {"abuseConfidenceScore": 101}},
        {"data": {**PAYLOAD["data"], "abuseConfidenceScore": 101}},
        {"data": {**PAYLOAD["data"], "abuseConfidenceScore": -1}},
        {"data": {**PAYLOAD["data"], "abuseConfidenceScore": "high"}},
        {"data": {**PAYLOAD["data"], "abuseConfidenceScore": 50.5}},
        {"data": {**PAYLOAD["data"], "abuseConfidenceScore": True}},
        {"data": {**PAYLOAD["data"], "numDistinctUsers": None}},
        {"data": {**PAYLOAD["data"], "totalReports": -3}},
        {"data": {**PAYLOAD["data"], "lastReportedAt": "yesterday"}},
    ],
)
async def test_a_malformed_answer_is_refused_not_trusted(body: object) -> None:
    with pytest.raises(Unavailable):
        await client_for(replying(200, body)).check("185.220.101.1")


async def test_a_body_that_is_not_json_is_refused() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b"<html>hi</html>"))

    with pytest.raises(Unavailable):
        await client_for(transport).check("185.220.101.1")


async def test_text_from_the_provider_is_cleaned_and_bounded() -> None:
    data = {**PAYLOAD["data"], "isp": "Evil\x1b[2K ISP\n" + "x" * 500, "usageType": 12}

    result = await client_for(replying(200, {"data": data})).check("185.220.101.1")

    assert result.reputation.isp is not None
    assert "\x1b" not in result.reputation.isp and "\n" not in result.reputation.isp
    assert len(result.reputation.isp) <= 100
    assert result.reputation.usage_type is None  # not a string


async def test_a_last_report_may_be_absent() -> None:
    data = {**PAYLOAD["data"], "lastReportedAt": None, "totalReports": 0, "numDistinctUsers": 0}

    result = await client_for(replying(200, {"data": data})).check("185.220.101.1")

    assert result.reputation.last_reported_at is None


@pytest.mark.parametrize(
    "ip", ["not-an-ip", "8.8.8.8&x=1", "", "1.2.3.4/24", "10.0.0.5", "192.168.1.1"]
)
async def test_only_public_addresses_are_ever_sent(ip: str) -> None:
    def never(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no request must be made")

    with pytest.raises(BadRequest):
        await client_for(httpx.MockTransport(never)).check(ip)


def test_the_provider_url_must_be_https() -> None:
    with pytest.raises(ValueError, match="https"):
        AbuseIpDbClient(KEY, base_url="http://api.abuseipdb.com")


def test_an_empty_key_is_refused() -> None:
    with pytest.raises(ValueError, match="key"):
        AbuseIpDbClient("")


async def test_the_key_never_appears_in_errors_or_repr() -> None:
    client = client_for(replying(401, {}))

    with pytest.raises(AuthRejected) as exc:
        await client.check("8.8.8.8")

    assert KEY not in str(exc.value) and KEY not in repr(exc.value) and KEY not in repr(client)


def test_the_default_http_client_never_follows_redirects() -> None:
    """The key is sent in a header: a redirect must not carry it to another host."""
    client = AbuseIpDbClient(KEY)

    assert client._http.follow_redirects is False


async def test_a_redirect_is_an_error_not_something_to_follow() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        return httpx.Response(302, headers={"Location": "https://evil.example/steal"})

    with pytest.raises(Unavailable):
        await client_for(httpx.MockTransport(handler)).check("185.220.101.1")

    assert seen == ["api.abuseipdb.com"]
