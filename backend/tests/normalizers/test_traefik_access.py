import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from sentinel_core.normalizers.base import ParseError, RawLog
from sentinel_core.normalizers.registry import NORMALIZERS
from sentinel_core.normalizers.traefik_access import (
    TRUNCATION_SUFFIX,
    TraefikAccessNormalizer,
    path_class,
)
from sentinel_core.schema.event import Action, Category, Outcome, Source

RECEIVED = datetime(2026, 9, 30, tzinfo=UTC)
# A line copied from the production access log (a probe answered 200 by the single-page app).
REAL = (
    '{"ClientAddr":"148.113.255.4:52654","ClientHost":"148.113.255.4","ClientPort":"52654",'
    '"ClientUsername":"-","DownstreamContentSize":397,"DownstreamStatus":200,"Duration":3454189,'
    '"OriginContentSize":397,"OriginDuration":3427197,"OriginStatus":200,"Overhead":26992,'
    '"RequestAddr":"sentinel.apps.auditflow.ca","RequestContentSize":0,"RequestCount":5,'
    '"RequestHost":"sentinel.apps.auditflow.ca","RequestMethod":"GET","RequestPath":"/.env",'
    '"RequestPort":"-","RequestProtocol":"HTTP/2.0","RequestScheme":"https","RetryAttempts":0,'
    '"RouterName":"sentinel@docker","ServiceAddr":"10.0.1.8:8000","ServiceName":"sentinel@docker",'
    '"ServiceURL":"http://10.0.1.8:8000","StartLocal":"2026-09-29T23:05:40.189830187Z",'
    '"StartUTC":"2026-09-29T23:05:40.189830187Z","TLSCipher":"TLS_AES_128_GCM_SHA256",'
    '"TLSVersion":"1.3","entryPointName":"https","level":"info","msg":"",'
    '"request_User-Agent":"test-scanner/1.0","time":"2026-09-29T23:05:40Z"}'
)


def raw(line: str) -> RawLog:
    return RawLog(
        agent_id=uuid4(),
        source=Source.TRAEFIK_ACCESS,
        origin="1:0",
        line=line,
        received_at=RECEIVED,
    )


def entry(**overrides: Any) -> str:
    document: dict[str, Any] = {
        "ClientHost": "203.0.113.9",
        "DownstreamStatus": 404,
        "RequestHost": "sentinel.example.org",
        "RequestMethod": "GET",
        "RequestPath": "/.env",
        "StartUTC": "2026-09-29T10:00:00.5Z",
        "entryPointName": "https",
        "request_User-Agent": "curl/8.5.0",
    }
    document.update(overrides)
    return json.dumps(document)


def test_a_real_production_line_becomes_a_web_event() -> None:
    event = TraefikAccessNormalizer().normalize(raw(REAL))

    assert event is not None
    assert (event.source, event.category, event.action) == (
        Source.TRAEFIK_ACCESS,
        Category.WEB,
        Action.HTTP_REQUEST,
    )
    assert str(event.src_ip) == "148.113.255.4"
    assert event.host == "sentinel.apps.auditflow.ca"
    assert event.dst_port == 443
    assert event.ts == datetime(2026, 9, 29, 23, 5, 40, 189830, tzinfo=UTC)
    # The app answered 200, yet it is flagged: the status does not make a probe harmless.
    assert event.outcome is Outcome.SUCCESS
    assert event.extra == {
        "method": "GET",
        "path": "/.env",
        "path_class": "sensitive",
        "status": 200,
        "user_agent": "test-scanner/1.0",
    }
    assert event.raw == REAL


def test_the_normalizer_is_registered_for_its_source() -> None:
    assert isinstance(NORMALIZERS[Source.TRAEFIK_ACCESS], TraefikAccessNormalizer)


@pytest.mark.parametrize(
    "path",
    [
        "/.env", "/.git/config", "/.GIT/HEAD", "/wp-login.php", "/wp-admin/setup-config.php",
        "/phpmyadmin/index.php", "/cgi-bin/luci", "/actuator/env", "/backup.sql", "/db.SQL",
        "/site.tar.gz", "/.npmrc", "/../../etc/passwd", "/a/..%2f..%2fetc/shadow", "/x/%2E%2E/y",
        "/download?f=/etc/passwd", "/proc/self/environ", "/.htpasswd",
    ],
)  # fmt: skip
def test_probe_paths_are_sensitive(path: str) -> None:
    assert path_class(path) == "sensitive"


@pytest.mark.parametrize(
    "path",
    [
        "/", "/alerts", "/v1/alerts/environment", "/backup-policy", "/blog/wp-login-tips",
        "/v1/incidents/console", "/docs/the-git-book", "/pma-guide", "/favicon.ico",
        "/assets/index-1a2b.js", "/v1/response/blocks", "",
    ],
)  # fmt: skip
def test_lookalikes_and_ordinary_paths_are_not(path: str) -> None:
    assert path_class(path) == "other"


def test_the_login_endpoint_has_its_own_class() -> None:
    assert path_class("/v1/auth/login") == "login"
    assert path_class("/v1/auth/login/extra") == "other"


def test_a_failed_login_is_a_failure_event() -> None:
    event = TraefikAccessNormalizer().normalize(
        raw(entry(RequestPath="/v1/auth/login", RequestMethod="POST", DownstreamStatus=401))
    )

    assert event is not None
    assert event.outcome is Outcome.FAILURE
    assert event.extra["path_class"] == "login"


def test_a_successful_login_is_kept_but_is_not_a_failure() -> None:
    event = TraefikAccessNormalizer().normalize(
        raw(entry(RequestPath="/v1/auth/login", RequestMethod="POST", DownstreamStatus=200))
    )

    assert event is not None and event.outcome is Outcome.SUCCESS


@pytest.mark.parametrize("status", [200, 204, 301, 304])
def test_an_ordinary_request_that_worked_is_not_stored(status: int) -> None:
    assert (
        TraefikAccessNormalizer().normalize(
            raw(entry(RequestPath="/alerts", DownstreamStatus=status))
        )
        is None
    )


@pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 500, 503])
def test_an_ordinary_request_that_failed_is_stored(status: int) -> None:
    event = TraefikAccessNormalizer().normalize(
        raw(entry(RequestPath="/some/page", DownstreamStatus=status))
    )

    assert event is not None
    assert event.outcome is Outcome.FAILURE and event.severity == 10
    assert event.extra["path_class"] == "other"


def test_the_plain_http_entry_point_is_port_80() -> None:
    event = TraefikAccessNormalizer().normalize(raw(entry(entryPointName="http")))

    assert event is not None and event.dst_port == 80


def test_an_ipv6_client_and_a_client_that_is_not_an_address() -> None:
    normalizer = TraefikAccessNormalizer()

    v6 = normalizer.normalize(raw(entry(ClientHost="2a00:1450:4007:80f::200e")))
    junk = normalizer.normalize(raw(entry(ClientHost="not-an-ip")))

    assert v6 is not None and str(v6.src_ip) == "2a00:1450:4007:80f::200e"
    assert junk is not None and junk.src_ip is None  # kept, but never trusted as an address


def test_attacker_controlled_fields_are_cut() -> None:
    event = TraefikAccessNormalizer().normalize(
        raw(entry(RequestPath="/.env" + "a" * 900, **{"request_User-Agent": "u" * 900}))
    )

    assert event is not None
    assert len(event.extra["path"]) == 512 and len(event.extra["user_agent"]) == 256


def truncated(path: str, **overrides: Any) -> str:
    """What the agent ships for a line above 8192 characters."""
    line = entry(RequestPath=path, **overrides)
    assert len(line) > 8192
    return line[: 8192 - len(TRUNCATION_SUFFIX)] + TRUNCATION_SUFFIX


def test_an_oversized_request_is_not_lost_to_the_dead_letter() -> None:
    line = truncated("/" + "A" * 9000, RequestMethod="POST", DownstreamStatus=414)

    event = TraefikAccessNormalizer().normalize(raw(line))

    assert event is not None
    assert str(event.src_ip) == "203.0.113.9"
    assert event.host == "sentinel.example.org"
    assert event.outcome is Outcome.FAILURE
    assert event.ts == RECEIVED  # the real timestamp was after the cut: receipt time stands in
    assert event.extra["truncated"] is True and event.extra["path_class"] == "sensitive"
    assert event.extra["method"] == "POST" and event.extra["status"] == 414
    assert len(event.extra["path"]) == 512


def test_a_truncated_line_that_lost_the_client_or_status_is_a_parse_error() -> None:
    # Cut inside the first key: nothing usable is left.
    cut = '{"ClientAddr":"203.0.113.9:5000","ClientHo' + TRUNCATION_SUFFIX
    with pytest.raises(ParseError):
        TraefikAccessNormalizer().normalize(raw(cut))


def test_only_the_agents_own_marker_triggers_the_salvage() -> None:
    with pytest.raises(ParseError):
        TraefikAccessNormalizer().normalize(
            raw('{"ClientHost":"203.0.113.9","DownstreamStatus":404')
        )


def test_the_event_id_is_deterministic() -> None:
    log = raw(REAL)
    first = TraefikAccessNormalizer().normalize(log)
    second = TraefikAccessNormalizer().normalize(log)

    assert first is not None and second is not None and first.event_id == second.event_id


@pytest.mark.parametrize(
    "line",
    [
        "",
        "not json",
        "[1, 2]",
        "{}",
        '{"RequestPath": "/"}',  # no status
        entry(DownstreamStatus="404"),
        entry(DownstreamStatus=True),
        entry(DownstreamStatus=99),
        entry(DownstreamStatus=600),
        entry(StartUTC="yesterday"),
        entry(StartUTC=None),
        '10.0.0.1 - - [29/Sep/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5',  # common log format
    ],
)
def test_malformed_lines_are_parse_errors(line: str) -> None:
    with pytest.raises(ParseError):
        TraefikAccessNormalizer().normalize(raw(line))
