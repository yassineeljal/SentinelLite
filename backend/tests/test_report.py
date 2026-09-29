"""The report page: drawn from a plain object (no database), then collected from a real one."""

from datetime import UTC, date, datetime, timedelta
from html.parser import HTMLParser

import pytest

from sentinel_core.db.alerts import MitreSummaryRow
from sentinel_core.report import (
    AgentRow,
    BlockRow,
    Report,
    RuleRow,
    SourceRow,
    render,
)

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
HOSTILE = '<script>alert("x")</script>&"\''


def full_report() -> Report:
    return Report(
        generated_at=NOW,
        days=7,
        alerts_total=14,
        alerts_by_day=[(date(2026, 9, 28), 4), (date(2026, 9, 29), 10)],
        by_rule=[RuleRow("ssh-bruteforce", 9, 60), RuleRow("web-path-probing", 5, 40)],
        top_sources=[SourceRow("45.83.64.10", "NL", 9, 2), SourceRow("2001:db8::1", None, 5, 1)],
        mitre=[MitreSummaryRow("T1110", 9, NOW - timedelta(hours=2))],
        events_by_source=[("linux.auth", 1200), ("traefik.access", 90)],
        dead_letters=3,
        blocks_by_mode={"enforce": 1, "dry_run": 4},
        recent_blocks=[
            BlockRow(
                "45.83.64.10", "enforce", "ssh-bruteforce", NOW - timedelta(hours=1), "active"
            ),
            BlockRow(
                "45.83.64.11", "dry_run", "ssh-bruteforce", NOW - timedelta(hours=3), "expired"
            ),
        ],
        actions_by_status={"done": 2, "failed": 1},
        agents=[
            AgentRow("vps-01", "linux", NOW - timedelta(minutes=1), False, False),
            AgentRow("dead-host", "linux", NOW - timedelta(hours=2), True, False),
            AgentRow("old", "linux", None, False, True),
        ],
        incidents_by_status={"new": 1, "closed": 2},
    )


class Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)


def test_the_page_is_self_contained_and_reads_well() -> None:
    page = render(full_report())

    assert page.startswith("<!doctype html>")
    for expected in [
        "SentinelLite security report",
        "Last 7 day(s)",
        "ssh-bruteforce",
        "45.83.64.10",
        "NL",
        "T1110",
        "linux.auth",
        "dry run (nothing applied)",
        "enforced",
    ]:
        assert expected in page
    assert "<script" not in page  # no script at all
    assert "http://" not in page and "https://" not in page  # nothing is loaded from elsewhere
    parser = Collector()
    parser.feed(page)
    assert {"table", "svg", "style", "section"} <= set(parser.tags)


def test_a_silent_agent_is_called_out_and_a_revoked_one_is_not() -> None:
    page = render(full_report())

    assert "1 agent(s) silent" in page
    assert page.count("SILENT") == 1
    assert "reporting" in page and "revoked" in page


def test_an_empty_period_still_renders_every_section() -> None:
    page = render(Report(generated_at=NOW, days=1))

    for message in [
        "No alert in this period.",
        "No alert with a source address in this period.",
        "No technique in this period.",
        "No block decided in this period.",
        "No agent registered.",
        "No event stored in this period.",
    ]:
        assert message in page


def test_text_that_comes_from_the_data_is_escaped_everywhere() -> None:
    report = full_report()
    report.by_rule = [RuleRow(HOSTILE, 1, 1)]
    report.top_sources = [SourceRow(HOSTILE, HOSTILE, 1, 1)]
    report.mitre = [MitreSummaryRow(HOSTILE, 1, NOW)]
    report.events_by_source = [(HOSTILE, 1)]
    report.recent_blocks = [BlockRow(HOSTILE, HOSTILE, HOSTILE, NOW, HOSTILE)]
    report.agents = [AgentRow(HOSTILE, HOSTILE, NOW, False, False)]
    report.actions_by_status = {HOSTILE: 1}
    report.incidents_by_status = {HOSTILE: 1}

    page = render(report)

    assert HOSTILE not in page
    assert "<script>alert" not in page
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in page


def test_the_chart_handles_a_single_day_and_a_long_period() -> None:
    one = Report(generated_at=NOW, days=1, alerts_by_day=[(date(2026, 9, 30), 5)])
    many = Report(
        generated_at=NOW,
        days=90,
        alerts_by_day=[(date(2026, 7, 1) + timedelta(days=i), i % 7) for i in range(90)],
    )

    assert "<rect" in render(one)
    page = render(many)
    assert page.count("<rect") == 90  # a zero-day gets a zero-height bar, still labelled by title
    assert "<svg" in page


@pytest.mark.parametrize("days", [0, -1])
async def test_a_period_must_be_positive(days: int) -> None:
    from sentinel_core.report import collect

    with pytest.raises(ValueError, match="positive"):
        await collect(None, days)  # type: ignore[arg-type]
