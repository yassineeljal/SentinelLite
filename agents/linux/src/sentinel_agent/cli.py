"""Command line entry point: `sentinel-agent --config /etc/sentinel-agent/agent.toml`.

Exit codes: 0 normal stop, 1 configuration error, 2 the server refused the key (revoked?),
3 the server refuses the log systematically, 4 server unreachable (--once only).
Codes 1-3 need a human: with systemd use RestartPreventExitStatus=1 2 3.
"""

import argparse
import logging
import signal
import sys
import threading
from pathlib import Path
from urllib.parse import urlsplit

from sentinel_agent import __version__
from sentinel_agent.client import IngestClient
from sentinel_agent.config import Config, ConfigError, load_config
from sentinel_agent.shipper import AuthenticationError, ProtocolError, Shipper, Unreachable
from sentinel_agent.state import StateStore

logger = logging.getLogger("sentinel_agent")

_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def transport_warning(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme == "http" and (parts.hostname or "") not in _LOOPBACK:
        return (
            f"sending logs and the API key in plaintext to {parts.netloc}: acceptable only on an "
            "isolated lab network, use https elsewhere"
        )
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel-agent", description="SentinelLite log agent")
    parser.add_argument("--config", type=Path, required=True, help="path of the TOML configuration")
    parser.add_argument(
        "--once", action="store_true", help="ship what is available, then exit (no follow mode)"
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=5,
        help="--once only: attempts to reach an unavailable server before giving up (default 5)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("--version", action="version", version=f"sentinel-agent {__version__}")
    return parser


def _run(config: Config, once: bool, retries: int) -> int:
    stop = threading.Event()
    if not once:
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda *_: stop.set())
    client = IngestClient(config.server_url, config.key, config.ca_file)
    shipper = Shipper(
        config,
        client,
        StateStore(config.state_file),
        stop,
        max_unavailable=retries if once else None,
        heartbeat=None if once else client.heartbeat,
    )
    try:
        if once:
            shipper.drain()
        else:
            shipper.run()
    except AuthenticationError as exc:
        logger.error("%s; not retrying: ask for a new key (sentinel agents create)", exc)
        return 2
    except ProtocolError as exc:
        logger.error("%s", exc)
        return 3
    except Unreachable as exc:
        logger.error("giving up: %s", exc)
        return 4
    logger.info("stopped (%d line(s) delivered, %d dropped)", shipper.sent, shipper.dropped)
    return 0


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
    warning = transport_warning(config.server_url)
    if warning:
        logger.warning(warning)
    logger.info(
        "sentinel-agent %s -> %s, %d source(s)", __version__, config.server_url, len(config.sources)
    )
    return _run(config, args.once, args.retries)


if __name__ == "__main__":
    sys.exit(main())
