"""Administration CLI: `sentinel agents create|list|revoke`.

In the compose stack:  docker compose exec api sentinel agents create --name ubuntu-01 --os linux
"""

import argparse
import asyncio
import sys
from uuid import UUID

from sentinel_core.auth.registry import VALID_OS, AgentNameTaken, PostgresAgentRepository
from sentinel_core.config import get_settings
from sentinel_core.db.session import create_engine, create_sessionmaker


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
    return parser


async def _run(args: argparse.Namespace) -> int:
    engine = create_engine(get_settings())
    try:
        registry = PostgresAgentRepository(create_sessionmaker(engine))
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
    finally:
        await engine.dispose()


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(_run(build_parser().parse_args(argv)))


if __name__ == "__main__":
    sys.exit(main())
