"""`sentinel alerts list|show` against a real Postgres."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core import cli
from sentinel_core.config import get_settings
from sentinel_core.db.alerts import insert_alerts, set_enrichment
from sentinel_core.db.events import insert_events
from sentinel_core.detection.alerts import Alert
from sentinel_core.enrichment.abuseipdb import Reputation
from sentinel_core.enrichment.enricher import Enrichment
from sentinel_core.enrichment.geoip import GeoInfo
from sentinel_core.enrichment.risk import assess
from sentinel_core.schema.event import Action, Category, Event, Outcome, Source
from tests.support import DATABASE_URL

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="SENTINEL_TEST_DATABASE_URL not set"),
]

AGENT = UUID("11111111-1111-1111-1111-111111111111")
T0 = datetime(2026, 9, 24, 15, 0, 0, tzinfo=UTC)
ALERT_ID = "ab" * 32


def event(n: int) -> Event:
    return Event(
        event_id=f"{n:064x}",
        ts=T0 + timedelta(seconds=n),
        received_at=T0 + timedelta(seconds=n, milliseconds=200),
        agent_id=AGENT,
        host="ubuntu-01",
        source=Source.LINUX_AUTH,
        category=Category.AUTHENTICATION,
        action=Action.LOGIN_FAILED,
        outcome=Outcome.FAILURE,
        severity=20,
        src_ip="203.0.113.7",
        user_name="root",
        raw=f"failed password attempt number {n}",
    )


def alert(alert_id: str = ALERT_ID, rule_id: str = "ssh-bruteforce", n: int = 3) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        title="SSH brute force",
        mitre=["T1110"],
        severity=60,
        ts=T0 + timedelta(seconds=n),
        group={"src_ip": "203.0.113.7"},
        src_ip="203.0.113.7",
        host="ubuntu-01",
        user_name="root",
        event_ids=[f"{i:064x}" for i in range(n, -1, -1)],  # newest first
        match_count=n + 1,
    )


@pytest.fixture
async def seeded(engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch) -> None:
    assert DATABASE_URL is not None
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions.begin() as session:
        await insert_events(session, [event(i) for i in range(4)])
        await insert_alerts(session, [alert(), alert("cd" * 32, "ssh-root-login", 1)])
    monkeypatch.setenv("SENTINEL_DATABASE_URL", DATABASE_URL)
    get_settings.cache_clear()


def test_list_shows_alerts_newest_first_and_can_filter_by_rule(
    seeded: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["alerts", "list"]) == 0
    out = capsys.readouterr().out
    lines = out.strip().splitlines()
    assert [line.split()[3] for line in lines] == ["ssh-bruteforce", "ssh-root-login"]
    assert "203.0.113.7" in lines[0] and ALERT_ID[:12] in lines[0]

    assert cli.main(["alerts", "list", "--rule", "ssh-root-login"]) == 0
    assert len(capsys.readouterr().out.strip().splitlines()) == 1

    assert cli.main(["alerts", "list", "--limit", "1"]) == 0
    assert len(capsys.readouterr().out.strip().splitlines()) == 1
    get_settings.cache_clear()


def test_show_prints_the_alert_its_evidence_and_the_detection_latency(
    seeded: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["alerts", "show", ALERT_ID[:10]]) == 0

    out = capsys.readouterr().out
    assert "ssh-bruteforce" in out and "T1110" in out and "src_ip=203.0.113.7" in out
    assert "failed password attempt number 0" in out  # evidence, oldest first
    assert out.index("attempt number 0") < out.index("attempt number 3")
    assert "detection latency" in out
    get_settings.cache_clear()


def test_show_rejects_unknown_ambiguous_and_malformed_ids(
    seeded: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["alerts", "show", "ef" * 8]) == 1  # unknown
    assert "not found" in capsys.readouterr().err

    assert cli.main(["alerts", "show", "aaaaaa"]) == 1  # valid hex, no match
    capsys.readouterr()

    assert cli.main(["alerts", "show", "%25%"]) == 1  # LIKE wildcards are not hex: refused
    assert "hexadecimal" in capsys.readouterr().err
    get_settings.cache_clear()


async def test_show_refuses_an_ambiguous_prefix(
    engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert DATABASE_URL is not None
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions.begin() as session:
        await insert_alerts(session, [alert("abcdef" + "01" * 29), alert("abcdef" + "02" * 29)])
    monkeypatch.setenv("SENTINEL_DATABASE_URL", DATABASE_URL)
    get_settings.cache_clear()

    assert await asyncio.to_thread(cli.main, ["alerts", "show", "abcdef"]) == 1

    assert "ambiguous" in capsys.readouterr().err
    get_settings.cache_clear()


async def test_attacker_controlled_fields_cannot_inject_terminal_escapes(
    engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert DATABASE_URL is not None
    hostile = "root\x1b]52;c;ZWNobyBwd25lZA==\x07\x1b[2K"
    trigger = event(0).model_copy(update={"raw": f"fake evidence\x1b[1A\x1b[2K {hostile}"})
    poisoned = alert("ef" * 32, n=0).model_copy(
        update={"user_name": hostile, "host": hostile, "group": {"src_ip": hostile}}
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions.begin() as session:
        await insert_events(session, [trigger])
        await insert_alerts(session, [poisoned])
    monkeypatch.setenv("SENTINEL_DATABASE_URL", DATABASE_URL)
    get_settings.cache_clear()

    assert await asyncio.to_thread(cli.main, ["alerts", "list"]) == 0
    listing = capsys.readouterr().out
    assert await asyncio.to_thread(cli.main, ["alerts", "show", "efefef"]) == 0
    detail = capsys.readouterr().out

    for output in (listing, detail):
        assert "\x1b" not in output and "\x07" not in output and "\r" not in output
        assert "\\x1b" in output  # visible, not silently dropped
    get_settings.cache_clear()


# --- enrichment ---------------------------------------------------------------------------------


async def enrich(engine: AsyncEngine, alert_id: str, enrichment: Enrichment) -> None:
    async with async_sessionmaker(engine, expire_on_commit=False).begin() as session:
        assert await set_enrichment(session, alert_id, enrichment, assess(60, enrichment))


async def test_show_and_list_display_where_the_source_is(
    seeded: None,
    engine: AsyncEngine,
    capsys: pytest.CaptureFixture[str],
) -> None:
    geo = GeoInfo(
        country_code="FR",
        country="France",
        city="Paris",
        latitude=48.85,
        longitude=2.35,
        asn=64500,
        as_org="Example Hosting SARL",
    )
    await enrich(engine, ALERT_ID, Enrichment(ip_scope="public", geo=geo))

    assert await asyncio.to_thread(cli.main, ["alerts", "show", ALERT_ID[:10]]) == 0
    shown = capsys.readouterr().out
    assert await asyncio.to_thread(cli.main, ["alerts", "list"]) == 0
    listed = capsys.readouterr().out.strip().splitlines()

    assert "from    Paris, France, FR  (48.85, 2.35)  AS64500 Example Hosting SARL" in shown
    assert listed[0].split()[5] == "FR"  # enriched alert: the country column
    assert listed[1].split()[5] != "FR"  # the other alert has no country ("-")
    get_settings.cache_clear()


async def test_show_says_when_there_is_nothing_to_show(
    seeded: None,
    engine: AsyncEngine,
    capsys: pytest.CaptureFixture[str],
) -> None:
    await enrich(engine, ALERT_ID, Enrichment(ip_scope="non_public"))

    assert await asyncio.to_thread(cli.main, ["alerts", "show", ALERT_ID[:10]]) == 0
    non_public = capsys.readouterr().out
    assert await asyncio.to_thread(cli.main, ["alerts", "show", "cd" * 4]) == 0
    not_enriched = capsys.readouterr().out

    assert "from    non-public address" in non_public
    assert "from    not enriched" in not_enriched
    get_settings.cache_clear()


async def test_hostile_values_in_the_enrichment_cannot_inject_terminal_escapes(
    seeded: None,
    engine: AsyncEngine,
    capsys: pytest.CaptureFixture[str],
) -> None:
    hostile = "Paris\x1b]52;c;ZWNobyBwd25lZA==\x07\x1b[2K"
    async with async_sessionmaker(engine).begin() as session:
        await session.execute(
            text("UPDATE alerts SET enrichment = CAST(:e AS jsonb) WHERE alert_id = :id"),
            {
                "id": ALERT_ID,
                "e": json.dumps(
                    {"ip_scope": "public", "geo": {"city": hostile, "asn": 1, "as_org": hostile}}
                ),
            },
        )

    assert await asyncio.to_thread(cli.main, ["alerts", "show", ALERT_ID[:10]]) == 0

    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "\\x1b" in out
    get_settings.cache_clear()


async def test_show_and_list_display_the_reputation(
    seeded: None,
    engine: AsyncEngine,
    capsys: pytest.CaptureFixture[str],
) -> None:
    reputation = Reputation(
        score=100,
        total_reports=1234,
        distinct_reporters=56,
        last_reported_at=datetime(2026, 9, 26, 13, 36, tzinfo=UTC),
        usage_type="Data Center",
        isp="Example Hosting",
        is_tor=True,
        checked_at=datetime(2026, 9, 26, 15, 0, tzinfo=UTC),
    )
    await enrich(engine, ALERT_ID, Enrichment(ip_scope="public", reputation=reputation))

    assert await asyncio.to_thread(cli.main, ["alerts", "show", ALERT_ID[:10]]) == 0
    shown = capsys.readouterr().out
    assert await asyncio.to_thread(cli.main, ["alerts", "list"]) == 0
    listed = capsys.readouterr().out.strip().splitlines()

    assert (
        "abuse   AbuseIPDB 100/100  1234 report(s) by 56 user(s), last 2026-09-26  "
        "Data Center  Example Hosting  Tor exit  checked 2026-09-26 15:00Z"
    ) in shown
    assert listed[0].split()[6] == "100" and listed[1].split()[6] == "-"
    get_settings.cache_clear()


async def test_show_says_when_there_is_no_reputation(
    seeded: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert await asyncio.to_thread(cli.main, ["alerts", "show", ALERT_ID[:10]]) == 0

    assert "abuse   no reputation" in capsys.readouterr().out
    get_settings.cache_clear()


async def test_hostile_values_in_the_reputation_cannot_inject_terminal_escapes(
    seeded: None, engine: AsyncEngine, capsys: pytest.CaptureFixture[str]
) -> None:
    hostile = "ISP\x1b]52;c;ZWNobyBwd25lZA==\x07\x1b[2K"
    stored = {"reputation": {"score": 5, "isp": hostile, "usage_type": hostile}}
    async with async_sessionmaker(engine).begin() as session:
        await session.execute(
            text("UPDATE alerts SET enrichment = CAST(:e AS jsonb) WHERE alert_id = :id"),
            {"id": ALERT_ID, "e": json.dumps(stored)},
        )

    assert await asyncio.to_thread(cli.main, ["alerts", "show", ALERT_ID[:10]]) == 0

    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    get_settings.cache_clear()


async def test_show_and_list_display_the_risk_and_its_factors(
    seeded: None, engine: AsyncEngine, capsys: pytest.CaptureFixture[str]
) -> None:
    reputation = Reputation(
        score=100,
        total_reports=5,
        distinct_reporters=3,
        is_tor=True,
        checked_at=datetime(2026, 9, 26, 15, 0, tzinfo=UTC),
    )
    await enrich(engine, ALERT_ID, Enrichment(ip_scope="public", reputation=reputation))

    assert await asyncio.to_thread(cli.main, ["alerts", "show", ALERT_ID[:10]]) == 0
    shown = capsys.readouterr().out
    assert await asyncio.to_thread(cli.main, ["alerts", "list"]) == 0
    listed = capsys.readouterr().out.strip().splitlines()

    assert "risk    90/100 (high)" in shown
    assert "+60 rule severity: severity 60 set by the rule" in shown
    assert "+25 reputation:" in shown and "+5 tor exit:" in shown
    assert listed[0].split()[7] == "90" and listed[1].split()[7] == "-"
    get_settings.cache_clear()


async def test_show_says_when_an_alert_has_not_been_scored(
    seeded: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert await asyncio.to_thread(cli.main, ["alerts", "show", ALERT_ID[:10]]) == 0

    assert "risk    not scored yet" in capsys.readouterr().out
    get_settings.cache_clear()


async def test_hostile_values_in_the_risk_cannot_inject_terminal_escapes(
    seeded: None, engine: AsyncEngine, capsys: pytest.CaptureFixture[str]
) -> None:
    hostile = "x\x1b]52;c;ZWNobyBwd25lZA==\x07\x1b[2K"
    stored = {
        "score": 50,
        "level": hostile,
        "factors": [{"name": hostile, "points": 5, "reason": hostile}],
    }
    async with async_sessionmaker(engine).begin() as session:
        await session.execute(
            text("UPDATE alerts SET risk = CAST(:r AS jsonb) WHERE alert_id = :id"),
            {"id": ALERT_ID, "r": json.dumps(stored)},
        )

    assert await asyncio.to_thread(cli.main, ["alerts", "show", ALERT_ID[:10]]) == 0

    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    get_settings.cache_clear()
