"""A printable security report (`sentinel report`): one self-contained HTML page.

No dependency and no script: open it in any browser and print it to PDF. Collecting the figures
(SQL, `collect`) is separate from drawing them (`render`, pure), so that the page can be tested
without a database. Everything that comes from the data is escaped: alert texts and host names
ultimately derive from log lines an attacker wrote.
"""

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from html import escape

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_core.db.alerts import MitreSummaryRow, mitre_summary

TOP = 10
RECENT_BLOCKS = 15


@dataclass(frozen=True)
class RuleRow:
    rule_id: str
    alerts: int
    max_severity: int


@dataclass(frozen=True)
class SourceRow:
    ip: str
    country: str | None
    alerts: int
    rules: int


@dataclass(frozen=True)
class BlockRow:
    ip: str
    mode: str
    rule_id: str
    created_at: datetime
    state: str


@dataclass(frozen=True)
class AgentRow:
    name: str
    os: str
    last_seen: datetime | None
    silent: bool
    revoked: bool


@dataclass
class Report:
    generated_at: datetime
    days: int
    alerts_total: int = 0
    alerts_by_day: list[tuple[date, int]] = field(default_factory=list)
    by_rule: list[RuleRow] = field(default_factory=list)
    top_sources: list[SourceRow] = field(default_factory=list)
    mitre: list[MitreSummaryRow] = field(default_factory=list)
    events_by_source: list[tuple[str, int]] = field(default_factory=list)
    dead_letters: int = 0
    blocks_by_mode: dict[str, int] = field(default_factory=dict)
    recent_blocks: list[BlockRow] = field(default_factory=list)
    actions_by_status: dict[str, int] = field(default_factory=dict)
    agents: list[AgentRow] = field(default_factory=list)
    incidents_by_status: dict[str, int] = field(default_factory=dict)


async def collect(session: AsyncSession, days: int, now: datetime | None = None) -> Report:
    if days <= 0:
        raise ValueError("days must be positive")
    now = now or datetime.now(UTC)
    report = Report(generated_at=now, days=days)
    window = {"days": days}

    rows = await session.execute(
        text(
            "SELECT date_trunc('day', ts)::date AS day, count(*) FROM alerts "
            "WHERE ts >= now() - make_interval(days => :days) GROUP BY 1 ORDER BY 1"
        ),
        window,
    )
    report.alerts_by_day = [(r[0], int(r[1])) for r in rows]
    report.alerts_total = sum(count for _, count in report.alerts_by_day)

    rows = await session.execute(
        text(
            "SELECT rule_id, count(*), max(severity) FROM alerts "
            "WHERE ts >= now() - make_interval(days => :days) "
            "GROUP BY rule_id ORDER BY count(*) DESC, rule_id"
        ),
        window,
    )
    report.by_rule = [RuleRow(r[0], int(r[1]), int(r[2])) for r in rows]

    rows = await session.execute(
        text(
            "SELECT host(src_ip), max(enrichment->'geo'->>'country_code'), count(*), "
            "count(DISTINCT rule_id) FROM alerts "
            "WHERE ts >= now() - make_interval(days => :days) AND src_ip IS NOT NULL "
            "GROUP BY src_ip ORDER BY count(*) DESC, host(src_ip) LIMIT :top"
        ),
        {**window, "top": TOP},
    )
    report.top_sources = [SourceRow(r[0], r[1], int(r[2]), int(r[3])) for r in rows]

    report.mitre = await mitre_summary(session, days=days)

    rows = await session.execute(
        text(
            "SELECT source, count(*) FROM events "
            "WHERE ts >= now() - make_interval(days => :days) "
            "GROUP BY source ORDER BY count(*) DESC, source"
        ),
        window,
    )
    report.events_by_source = [(r[0], int(r[1])) for r in rows]

    dead = await session.execute(
        text(
            "SELECT count(*) FROM events_dead_letter "
            "WHERE received_at >= now() - make_interval(days => :days)"
        ),
        window,
    )
    report.dead_letters = int(dead.scalar_one())

    rows = await session.execute(
        text(
            "SELECT mode, count(*) FROM blocked_ips "
            "WHERE created_at >= now() - make_interval(days => :days) GROUP BY mode"
        ),
        window,
    )
    report.blocks_by_mode = {r[0]: int(r[1]) for r in rows}

    rows = await session.execute(
        text(
            "SELECT host(ip), mode, rule_id, created_at, CASE WHEN released_at IS NOT NULL "
            "THEN 'released' WHEN expires_at <= now() THEN 'expired' ELSE 'active' END "
            "FROM blocked_ips WHERE created_at >= now() - make_interval(days => :days) "
            "ORDER BY created_at DESC, id DESC LIMIT :n"
        ),
        {**window, "n": RECENT_BLOCKS},
    )
    report.recent_blocks = [BlockRow(r[0], r[1], r[2], r[3], r[4]) for r in rows]

    rows = await session.execute(
        text(
            "SELECT status, count(*) FROM agent_actions "
            "WHERE created_at >= now() - make_interval(days => :days) GROUP BY status"
        ),
        window,
    )
    report.actions_by_status = {r[0]: int(r[1]) for r in rows}

    rows = await session.execute(
        text(
            "SELECT name, os, last_seen_at, silent_since IS NOT NULL, revoked_at IS NOT NULL "
            "FROM agents ORDER BY name"
        )
    )
    report.agents = [AgentRow(r[0], r[1], r[2], bool(r[3]), bool(r[4])) for r in rows]

    rows = await session.execute(text("SELECT status, count(*) FROM incidents GROUP BY status"))
    report.incidents_by_status = {r[0]: int(r[1]) for r in rows}
    return report


# -- drawing ---------------------------------------------------------------------------------

_STYLE = """
:root { color-scheme: light dark; --fg:#1b1f24; --muted:#59636e; --line:#d0d7de; --bg:#fff;
        --accent:#0969da; --bad:#cf222e; --ok:#1a7f37; --warn:#9a6700; }
@media (prefers-color-scheme: dark) { :root { --fg:#e6edf3; --muted:#9198a1; --line:#30363d;
        --bg:#0d1117; --accent:#4493f8; --bad:#f85149; --ok:#3fb950; --warn:#d29922; } }
@media print { :root { --fg:#000; --muted:#444; --line:#bbb; --bg:#fff; --accent:#0550ae; }
        section { break-inside: avoid; } }
body { font: 14px/1.5 system-ui, sans-serif; color: var(--fg); background: var(--bg);
       max-width: 900px; margin: 2rem auto; padding: 0 1rem; }
h1 { margin-bottom: 0; } h2 { border-bottom: 1px solid var(--line); padding-bottom: .2rem;
       margin-top: 2rem; }
.sub { color: var(--muted); margin-top: .2rem; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0; }
th, td { text-align: left; padding: .3rem .6rem; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; } td.n, th.n { text-align: right; }
.cards { display: flex; gap: .8rem; flex-wrap: wrap; }
.card { border: 1px solid var(--line); border-radius: 8px; padding: .6rem 1rem; min-width: 8rem; }
.card b { display: block; font-size: 1.6rem; } .card span { color: var(--muted); }
.bad { color: var(--bad); font-weight: 600; } .ok { color: var(--ok); }
.warn { color: var(--warn); } code { font-family: ui-monospace, monospace; }
svg text { fill: var(--muted); font-size: 10px; } svg rect { fill: var(--accent); }
.note { color: var(--muted); font-size: 12px; }
"""


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _table(headers: list[tuple[str, bool]], rows: list[list[object]], empty: str) -> str:
    if not rows:
        return f'<p class="note">{_e(empty)}</p>'
    head = "".join(f'<th class="n">{_e(h)}</th>' if n else f"<th>{_e(h)}</th>" for h, n in headers)
    body = "".join(
        "<tr>"
        + "".join(
            f'<td class="n">{cell}</td>' if headers[i][1] else f"<td>{cell}</td>"
            for i, cell in enumerate(row)
        )
        + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _bars(series: list[tuple[date, int]]) -> str:
    if not series:
        return '<p class="note">No alert in this period.</p>'
    width, height, gap = 860, 110, 4
    peak = max(count for _, count in series)
    bar = max(4, (width - gap * len(series)) // len(series))
    parts = [f'<svg viewBox="0 0 {width} {height + 22}" role="img" aria-label="Alerts per day">']
    for i, (day, count) in enumerate(series):
        h = max(2, round(count / peak * height)) if count else 0
        x = i * (bar + gap)
        parts.append(
            f'<rect x="{x}" y="{height - h}" width="{bar}" height="{h}">'
            f"<title>{_e(day)}: {count}</title></rect>"
        )
        if len(series) <= 16 or i % max(1, len(series) // 8) == 0:
            parts.append(f'<text x="{x}" y="{height + 14}">{_e(f"{day:%m-%d}")}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _stamp(value: datetime) -> str:
    return f"{value:%Y-%m-%d %H:%M}"


def _when(value: datetime | None) -> str:
    return "never" if value is None else f"{value:%Y-%m-%d %H:%M}Z"


def render(report: Report) -> str:
    silent = sum(1 for a in report.agents if a.silent and not a.revoked)
    enforced = report.blocks_by_mode.get("enforce", 0)
    dry = report.blocks_by_mode.get("dry_run", 0)
    cards = [
        (report.alerts_total, "alerts"),
        (len({r.rule_id for r in report.by_rule}), "rules that fired"),
        (sum(n for _, n in report.events_by_source), "events stored"),
        (enforced, "blocks applied"),
        (dry, "blocks (dry run)"),
        (report.dead_letters, "dead-lettered lines"),
    ]
    sections = [
        "<h1>SentinelLite security report</h1>"
        f'<p class="sub">Last {report.days} day(s) · '
        f"generated {_e(_stamp(report.generated_at))} UTC</p>",
        '<div class="cards">'
        + "".join(
            f'<div class="card"><b>{n}</b><span>{_e(label)}</span></div>' for n, label in cards
        )
        + "</div>",
        "<section><h2>Alerts per day</h2>" + _bars(report.alerts_by_day) + "</section>",
        "<section><h2>Alerts by rule</h2>"
        + _table(
            [("Rule", False), ("Alerts", True), ("Highest severity", True)],
            [[f"<code>{_e(r.rule_id)}</code>", r.alerts, r.max_severity] for r in report.by_rule],
            "No alert in this period.",
        )
        + "</section>",
        f"<section><h2>Top {TOP} sources</h2>"
        + _table(
            [("Address", False), ("Country", False), ("Alerts", True), ("Distinct rules", True)],
            [
                [f"<code>{_e(s.ip)}</code>", _e(s.country or "unknown"), s.alerts, s.rules]
                for s in report.top_sources
            ],
            "No alert with a source address in this period.",
        )
        + "</section>",
        "<section><h2>MITRE ATT&amp;CK techniques seen</h2>"
        + _table(
            [("Technique", False), ("Alerts", True), ("Latest", False)],
            [
                [f"<code>{_e(m.technique)}</code>", m.count, _e(_when(m.latest_ts))]
                for m in report.mitre
            ],
            "No technique in this period.",
        )
        + "</section>",
        "<section><h2>Response</h2>"
        + _table(
            [
                ("Address", False),
                ("Mode", False),
                ("Rule", False),
                ("Since", False),
                ("State", False),
            ],
            [
                [
                    f"<code>{_e(b.ip)}</code>",
                    "enforced" if b.mode == "enforce" else "dry run (nothing applied)",
                    f"<code>{_e(b.rule_id)}</code>",
                    _e(_when(b.created_at)),
                    _e(b.state),
                ]
                for b in report.recent_blocks
            ],
            "No block decided in this period.",
        )
        + '<p class="note">Agent actions: '
        + _e(", ".join(f"{n} {s}" for s, n in sorted(report.actions_by_status.items())) or "none")
        + ". Incidents: "
        + _e(", ".join(f"{n} {s}" for s, n in sorted(report.incidents_by_status.items())) or "none")
        + ".</p></section>",
        "<section><h2>Collection health</h2>"
        + _table(
            [("Agent", False), ("OS", False), ("Last seen", False), ("Status", False)],
            [
                [
                    _e(a.name),
                    _e(a.os),
                    _e(_when(a.last_seen)),
                    '<span class="warn">revoked</span>'
                    if a.revoked
                    else '<span class="bad">SILENT</span>'
                    if a.silent
                    else '<span class="ok">reporting</span>',
                ]
                for a in report.agents
            ],
            "No agent registered.",
        )
        + _table(
            [("Source", False), ("Events", True)],
            [[f"<code>{_e(s)}</code>", n] for s, n in report.events_by_source],
            "No event stored in this period.",
        )
        + (
            f'<p class="bad">{silent} agent(s) silent: detection is blind on them.</p>'
            if silent
            else ""
        )
        + "</section>",
        '<p class="note">Generated by <code>sentinel report</code>. Counts are alerts (a rule '
        "firing once per source per cooldown), not raw attempts.</p>",
    ]
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>SentinelLite report</title><style>{_STYLE}</style></head><body>"
        + "".join(sections)
        + "</body></html>"
    )
