"""`sentinel report` against a real database."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from sentinel_core import cli
from sentinel_core.db.alerts import insert_alerts
from sentinel_core.report import collect, render
from tests.db.test_incidents_integration import alert
from tests.support import DATABASE_URL

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(DATABASE_URL is None, reason="SENTINEL_TEST_DATABASE_URL not set"),
]


async def test_a_report_over_an_empty_database_renders(engine: AsyncEngine) -> None:
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async with sessions() as session:
        report = await collect(session, 7)

    assert report.alerts_total == 0 and report.agents == [] and report.dead_letters == 0
    assert "No alert in this period." in render(report)


async def test_alerts_agents_and_blocks_are_summarised(engine: AsyncEngine) -> None:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions.begin() as session:
        await insert_alerts(session, [alert("a" * 64), alert("b" * 64)])
        await session.execute(
            text(
                "INSERT INTO agents (id, name, os, key_hash, last_seen_at, silent_since) VALUES "
                "(gen_random_uuid(), 'quiet', 'linux', 'x', now() - interval '2 hours', now())"
            )
        )
        await session.execute(
            text(
                "INSERT INTO blocked_ips (ip, alert_id, rule_id, reason, mode, expires_at) "
                "VALUES ('45.83.64.10', :a, 'ssh-bruteforce', 'r', 'enforce', "
                "now() + interval '1 hour')"
            ),
            {"a": "c" * 64},
        )

    async with sessions() as session:
        report = await collect(session, 30, datetime.now(UTC) + timedelta(days=0))

    assert report.alerts_total == 2
    assert report.by_rule and report.by_rule[0].alerts == 2
    assert report.blocks_by_mode == {"enforce": 1}
    assert [(b.ip, b.state) for b in report.recent_blocks] == [("45.83.64.10", "active")]
    assert [(a.name, a.silent) for a in report.agents] == [("quiet", True)]
    page = render(report)
    assert "quiet" in page and "SILENT" in page and "45.83.64.10" in page


async def test_the_cli_writes_a_file_or_stdout_and_refuses_a_bad_period(
    engine: AsyncEngine, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    parser = cli.build_parser()
    target = tmp_path / "report.html"

    assert await cli._report(parser.parse_args(["report", "--output", str(target)]), sessions) == 0
    assert target.read_text().startswith("<!doctype html>")
    assert "print it to PDF" in capsys.readouterr().err

    assert await cli._report(parser.parse_args(["report", "--days", "3"]), sessions) == 0
    assert capsys.readouterr().out.startswith("<!doctype html>")

    for bad in ("0", "366", "-4"):
        assert await cli._report(parser.parse_args(["report", "--days", bad]), sessions) == 1
