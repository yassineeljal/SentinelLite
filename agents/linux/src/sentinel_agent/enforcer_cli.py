"""`sentinel-agent-enforcer --config /etc/sentinel-agent/agent.toml`

A separate process from the log shipper on purpose: it needs the privilege to change the firewall,
the shipper must not have it. Reads the same configuration file (the `[response]` section).

Exit codes: 0 normal stop, 1 configuration error (or no [response] section), 2 key refused.
"""

import argparse
import logging
import signal
import sys
import threading
from datetime import timedelta
from pathlib import Path

from sentinel_agent import __version__
from sentinel_agent.actions import ActionClient
from sentinel_agent.blocks import BlockStore
from sentinel_agent.cli import transport_warning
from sentinel_agent.config import ConfigError, load_config
from sentinel_agent.enforcer import AuthenticationError, Enforcer
from sentinel_agent.firewall import (
    Backend,
    FirewallError,
    IptablesBackend,
    LogOnlyBackend,
    parse_networks,
)

logger = logging.getLogger("sentinel_agent.enforcer")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel-agent-enforcer", description="SentinelLite agent: applies firewall blocks"
    )
    parser.add_argument("--config", type=Path, required=True, help="path of the TOML configuration")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("--version", action="version", version=f"sentinel-agent {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    response = config.response
    if response is None:
        print("error: no [response] section: this agent is not set up to block", file=sys.stderr)
        return 1
    warning = transport_warning(config.server_url)
    if warning:
        logger.warning(warning)

    backend: Backend = IptablesBackend() if response.backend == "iptables" else LogOnlyBackend()
    enforcer = Enforcer(
        ActionClient(config.server_url, config.key, config.ca_file),
        backend,
        BlockStore(response.state_file),
        never_block=parse_networks(response.never_block),
        max_blocks=response.max_blocks,
        max_ttl=timedelta(seconds=response.max_ttl_seconds),
    )
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stop.set())
    logger.info(
        "sentinel-agent-enforcer %s -> %s (backend %s)",
        __version__,
        config.server_url,
        response.backend,
    )
    try:
        enforcer.run(stop, response.poll_interval)
    except AuthenticationError as exc:
        logger.error("%s; not retrying: ask for a new key (sentinel agents create)", exc)
        return 2
    except FirewallError as exc:
        print(f"error: firewall unusable: {exc}", file=sys.stderr)
        return 1
    logger.info(
        "stopped (%d block(s) applied, %d lifted, %d refused)",
        enforcer.applied,
        enforcer.lifted,
        enforcer.refused,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
