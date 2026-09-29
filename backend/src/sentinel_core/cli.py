"""Administration CLI: `sentinel agents|users create|list|revoke`, `sentinel alerts list|show`,
`sentinel blocks`, `sentinel unblock`, `sentinel allowlist add|list|remove`.

In the compose stack:  docker compose exec api sentinel agents create --name ubuntu-01 --os linux
`sentinel users create` is the only way to get a dashboard account: there is no self-registration.
`sentinel alerts` remains available alongside the (now authenticated) `/v1/alerts` HTTP endpoint.
"""

import argparse
import asyncio
import getpass
import re
import sys
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel_core import bench
from sentinel_core.auth.passwords import WeakPassword
from sentinel_core.auth.registry import VALID_OS, AgentNameTaken, PostgresAgentRepository
from sentinel_core.auth.user_registry import VALID_ROLES, EmailTaken, PostgresUserRepository
from sentinel_core.config import get_settings
from sentinel_core.db.actions import release_blocks_for_ip
from sentinel_core.db.alerts import AmbiguousAlertId, get_alert, list_alerts
from sentinel_core.db.responses import (
    AllowlistEntryExists,
    add_allowlist,
    canonical,
    list_allowlist,
    list_blocks,
    record_audit,
    remove_allowlist,
)
from sentinel_core.db.session import create_engine, create_sessionmaker
from sentinel_core.terminal import sanitize

# Alert id prefixes are used in a LIKE pattern: only hexadecimal is accepted (no wildcards).
_HEX = re.compile(r"^[0-9a-f]{6,64}$")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel", description="SentinelLite administration")
    sub = parser.add_subparsers(dest="group", required=True)

    agents = sub.add_parser("agents", help="manage collection agents").add_subparsers(
        dest="command", required=True
    )
    create = agents.add_parser("create", help="register an agent and print its API key once")
    create.add_argument("--name", required=True)
    create.add_argument("--os", required=True, choices=VALID_OS)
    agents.add_parser("list", help="list agents (never shows keys)")
    revoke = agents.add_parser("revoke", help="revoke an agent's key")
    revoke.add_argument("agent_id", type=UUID)

    alerts = sub.add_parser("alerts", help="inspect detections").add_subparsers(
        dest="command", required=True
    )
    listing = alerts.add_parser("list", help="most recent alerts first")
    listing.add_argument("--limit", type=int, default=20)
    listing.add_argument("--rule", help="only alerts of this rule id")
    show = alerts.add_parser("show", help="one alert with its evidence and detection latency")
    show.add_argument("alert_id", help="alert id or unambiguous hexadecimal prefix")

    users = sub.add_parser("users", help="manage dashboard accounts").add_subparsers(
        dest="command", required=True
    )
    ucreate = users.add_parser("create", help="create a dashboard account (prompts for a password)")
    ucreate.add_argument("--email", required=True)
    ucreate.add_argument("--role", required=True, choices=VALID_ROLES)
    users.add_parser("list", help="list dashboard accounts (never shows password hashes)")
    urevoke = users.add_parser("revoke", help="revoke a user and every one of their sessions")
    urevoke.add_argument("user_id", type=UUID)

    blocks = sub.add_parser("blocks", help="addresses the responder blocked (or would block)")
    blocks.set_defaults(command="list")
    blocks.add_argument("--limit", type=int, default=20)

    unblock = sub.add_parser("unblock", help="lift the active blocks of an address, now")
    unblock.add_argument("address")

    allowlist = sub.add_parser("allowlist", help="networks that are never blocked").add_subparsers(
        dest="command", required=True
    )
    aadd = allowlist.add_parser("add", help="protect an address or CIDR (e.g. your own)")
    aadd.add_argument("cidr")
    aadd.add_argument("--note", default="")
    allowlist.add_parser("list", help="list the protected networks")
    aremove = allowlist.add_parser("remove", help="stop protecting an address or CIDR")
    aremove.add_argument("cidr")

    bench.add_arguments(
        sub.add_parser("bench", help="replay the attack/benign scenarios: detection and FP figures")
    )
    return parser


async def _run(args: argparse.Namespace) -> int:
    engine = create_engine(get_settings())
    try:
        if args.group == "alerts":
            return await _alerts(args, create_sessionmaker(engine))
        if args.group in ("blocks", "unblock", "allowlist"):
            return await _response(args, create_sessionmaker(engine))
        if args.group == "users":
            return await _users(args, PostgresUserRepository(create_sessionmaker(engine)))
        return await _agents(args, PostgresAgentRepository(create_sessionmaker(engine)))
    finally:
        await engine.dispose()


async def _agents(args: argparse.Namespace, registry: PostgresAgentRepository) -> int:
    if args.command == "create":
        try:
            created = await registry.create_agent(name=args.name, os=args.os)
        except (AgentNameTaken, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"created agent {created.agent.name} ({created.agent.id})")
        print(f"key: {created.token}")
        print("Store this key now: it cannot be shown again.", file=sys.stderr)
        return 0
    if args.command == "revoke":
        if await registry.revoke_agent(args.agent_id):
            print(f"revoked {args.agent_id}")
            return 0
        print("error: unknown or already revoked agent", file=sys.stderr)
        return 1
    for agent in await registry.list_agents():
        status = "revoked" if agent.revoked_at else "active"
        since = f"{agent.created_at:%Y-%m-%d}"
        print(f"{agent.id}  {agent.name:<24} {agent.os:<8} {status:<8} {since}")
    return 0


async def _users(args: argparse.Namespace, registry: PostgresUserRepository) -> int:
    if args.command == "create":
        first = getpass.getpass("Password: ")
        second = getpass.getpass("Confirm password: ")
        if first != second:
            print("error: the two passwords did not match", file=sys.stderr)
            return 1
        try:
            created = await registry.create_user(args.email, first, args.role)
        except (EmailTaken, ValueError, WeakPassword) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"created user {created.email} ({created.id}), role {created.role}")
        return 0
    if args.command == "revoke":
        if await registry.revoke_user(args.user_id):
            print(f"revoked {args.user_id} (and every one of their sessions)")
            return 0
        print("error: unknown or already revoked user", file=sys.stderr)
        return 1
    for user in await registry.list_users():
        status = "revoked" if user.revoked_at else "active"
        since = f"{user.created_at:%Y-%m-%d}"
        print(f"{user.id}  {sanitize(user.email):<32} {user.role:<8} {status:<8} {since}")
    return 0


async def _response(args: argparse.Namespace, sessions: async_sessionmaker[AsyncSession]) -> int:
    async with sessions.begin() as session:
        if args.group == "unblock":
            return await _unblock(session, args.address)
        if args.group == "blocks":
            for b in await list_blocks(session, limit=args.limit):
                state = "released" if b.released_at else "active"
                print(
                    f"{b.created_at:%Y-%m-%d %H:%M:%S}  {b.mode:<8} {sanitize(b.ip):<40} "
                    f"until {b.expires_at:%m-%d %H:%M}  {state:<8} {sanitize(b.reason)}"
                )
            return 0
        if args.command == "list":
            for e in await list_allowlist(session):
                print(f"{sanitize(e.cidr):<40} {e.created_at:%Y-%m-%d}  {sanitize(e.note)}")
            return 0
        try:
            if args.command == "add":
                added = await add_allowlist(session, args.cidr, args.note, "cli")
                print(f"protected {added}: it will never be blocked")
                return 0
            if await remove_allowlist(session, args.cidr, "cli"):
                print(f"removed {args.cidr} from the allowlist")
                return 0
        except AllowlistEntryExists as exc:
            print(f"error: {exc} is already on the allowlist", file=sys.stderr)
            return 1
        except ValueError as exc:
            print(f"error: not a valid address or CIDR: {exc}", file=sys.stderr)
            return 1
        print("error: not on the allowlist", file=sys.stderr)
        return 1


async def _unblock(session: AsyncSession, address: str) -> int:
    try:
        ip = canonical(address)
    except ValueError:
        print(f"error: not an IP address: {sanitize(address)[:64]}", file=sys.stderr)
        return 1
    released = await release_blocks_for_ip(session, ip, "cli", datetime.now(UTC))
    if not released:
        print(f"{ip} has no active block", file=sys.stderr)
        return 1
    await record_audit(session, "cli", "unblock.manual", ip, {"block_ids": released})
    print(
        f"lifted {len(released)} block(s) of {ip}: the agents drop their rule at their next poll.\n"
        f"If it attacks again it will be blocked again: `sentinel allowlist add {ip}` to stop that."
    )
    return 0


async def _alerts(args: argparse.Namespace, sessions: async_sessionmaker[AsyncSession]) -> int:
    async with sessions() as session:
        if args.command == "list":
            for a in await list_alerts(session, limit=args.limit, rule_id=args.rule):
                print(
                    f"{a.ts:%Y-%m-%d %H:%M:%S}  {a.severity:>3}  {sanitize(a.rule_id):<20} "
                    f"{sanitize(a.src_ip):<16} {sanitize(a.country_code):<3} "
                    f"{'-' if a.abuse_score is None else a.abuse_score:>3} "
                    f"{'-' if a.risk_score is None else a.risk_score:>3} "
                    f"{sanitize(a.host):<14} {sanitize(a.user_name):<10} "
                    f"x{a.match_count:<3} {a.alert_id[:12]}"
                )
            return 0

        if not _HEX.fullmatch(args.alert_id):
            print(
                "error: the alert id must be hexadecimal (at least 6 characters)", file=sys.stderr
            )
            return 1
        try:
            detail = await get_alert(session, args.alert_id)
        except AmbiguousAlertId:
            print("error: ambiguous id prefix, give more characters", file=sys.stderr)
            return 1
        if detail is None:
            print("error: alert not found", file=sys.stderr)
            return 1
        a = detail.summary
        group = " ".join(f"{sanitize(k)}={sanitize(str(v))}" for k, v in detail.group.items())
        mitre = ", ".join(sanitize(t) for t in detail.mitre)
        print(f"{sanitize(a.rule_id)}: {sanitize(a.title)}  [{mitre}]  severity {a.severity}")
        print(f"id      {a.alert_id}")
        print(f"time    {a.ts:%Y-%m-%d %H:%M:%S} UTC (stored {a.created_at:%H:%M:%S})")
        print(f"who     {group}  host={sanitize(a.host)}  user={sanitize(a.user_name)}")
        print(f"from    {_where(detail.enrichment)}")
        print(f"abuse   {_reputation(detail.enrichment)}")
        for line in _risk(detail.risk):
            print(line)
        print(f"count   {a.match_count} event(s), {len(detail.evidence)} shown")
        if detail.detection_latency is not None:
            ms = detail.detection_latency.total_seconds() * 1000
            print(f"detection latency  {ms:.0f} ms (line received -> alert stored)")
        print("evidence (oldest first):")
        for e in detail.evidence:
            print(f"  {e.ts:%H:%M:%S}  {sanitize(e.action):<13} {sanitize(e.raw)}")
        return 0


def _where(enrichment: dict[str, Any] | None) -> str:
    """One line about the source address from the stored enrichment (all values sanitised)."""
    if enrichment is None:
        return "not enriched (no source address, or the enricher has not run yet)"
    if enrichment.get("ip_scope") == "non_public":
        return "non-public address (private, loopback or reserved): no location"
    geo = enrichment.get("geo")
    if not isinstance(geo, dict) or not geo:
        return "public address, unknown to the GeoIP databases"
    place = ", ".join(
        sanitize(str(geo[key])) for key in ("city", "country", "country_code") if geo.get(key)
    )
    parts = [place or "location unknown"]
    if geo.get("latitude") is not None and geo.get("longitude") is not None:
        parts.append(f"({float(geo['latitude']):.2f}, {float(geo['longitude']):.2f})")
    if geo.get("asn") is not None:
        parts.append(f"AS{int(geo['asn'])} {sanitize(str(geo.get('as_org') or ''))}".rstrip(" -"))
    return "  ".join(parts)


def _reputation(enrichment: dict[str, Any] | None) -> str:
    """One line from the stored AbuseIPDB reputation (all values sanitised)."""
    rep = (enrichment or {}).get("reputation")
    if not isinstance(rep, dict):
        return "no reputation (provider off, address not public, or no answer at the time)"
    last = str(rep.get("last_reported_at") or "")[:10] or "never"
    flags = [
        name
        for key, name in (("is_tor", "Tor exit"), ("is_whitelisted", "whitelisted"))
        if rep.get(key)
    ]
    details = [sanitize(str(rep[k])) for k in ("usage_type", "isp") if rep.get(k)]
    reports, users = int(rep.get("total_reports", 0)), int(rep.get("distinct_reporters", 0))
    parts = [
        f"AbuseIPDB {int(rep.get('score', 0))}/100",
        f"{reports} report(s) by {users} user(s), last {sanitize(last)}",
        *details,
        *flags,
        f"checked {sanitize(str(rep.get('checked_at') or '?')[:16].replace('T', ' '))}Z",
    ]
    return "  ".join(parts)


def _risk(risk: dict[str, Any] | None) -> list[str]:
    """The risk score and, one per line, the factors that make it (all values sanitised)."""
    if not isinstance(risk, dict):
        return ["risk    not scored yet (the enricher has not processed this alert)"]
    lines = [f"risk    {int(risk.get('score', 0))}/100 ({sanitize(str(risk.get('level', '?')))})"]
    for factor in risk.get("factors") or []:
        if isinstance(factor, dict):
            points = int(factor.get("points", 0))
            name, reason = sanitize(str(factor.get("name"))), sanitize(str(factor.get("reason")))
            lines.append(f"          {points:+d} {name}: {reason}")
    return lines


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.group == "bench":  # needs neither the database nor the settings
        return bench.run_command(args)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
