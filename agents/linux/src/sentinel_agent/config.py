"""Agent configuration: a TOML file plus the API key from a private file or the environment.

Everything is validated up front and unknown keys are refused, so that a typo fails loudly at
startup instead of silently changing behaviour on a monitored host.
"""

import os
import re
import stat
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sentinel_agent.firewall import parse_networks

# Sources a Linux agent can ship (the server knows more, e.g. the Windows ones).
LINUX_SOURCES = ("linux.auth", "nginx.access", "traefik.access")
# Limits of the ingestion API (docs/INGESTION_API.md): 500 lines per request, 8 MiB per body.
# JSON escaping can multiply the size of control characters by 6, hence the byte ceiling.
MAX_BATCH_LINES = 500
MIN_BATCH_BYTES = 1024
MAX_BATCH_BYTES = 1_300_000
ENV_KEY = "SENTINEL_AGENT_KEY"

_KEY_PATTERN = re.compile(r"^[0-9a-fA-F-]{36}\.[A-Za-z0-9_-]{32,128}$")


class ConfigError(Exception):
    """The configuration is invalid; the message says what to fix."""


@dataclass(frozen=True)
class Source:
    path: Path
    source: str


@dataclass(frozen=True)
class ResponseConfig:
    """Settings of the enforcer (`sentinel-agent-enforcer`); absent = this agent never blocks."""

    backend: str
    never_block: tuple[str, ...]
    poll_interval: float = 5.0
    state_file: Path = Path("/var/lib/sentinel-agent/blocks.json")
    max_blocks: int = 100
    max_ttl_seconds: int = 86_400


@dataclass(frozen=True)
class Config:
    server_url: str
    key: str = ""
    sources: tuple[Source, ...] = ()
    state_file: Path = Path("/var/lib/sentinel-agent/state.json")
    batch_lines: int = 200
    batch_bytes: int = 1_048_576
    start_at: str = "end"
    poll_interval: float = 0.5
    ca_file: Path | None = None
    response: ResponseConfig | None = None

    def __repr__(self) -> str:  # never let the key reach a log or a traceback
        return f"Config(server_url={self.server_url!r}, sources={len(self.sources)}, key=<hidden>)"


def _only_keys(section: str, data: Mapping[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        hint = " (put the key in server.key_file or SENTINEL_AGENT_KEY)" if "key" in unknown else ""
        raise ConfigError(f"[{section}]: unknown key(s) {', '.join(unknown)}{hint}")


def _int_in(data: Mapping[str, Any], name: str, default: int, low: int, high: int) -> int:
    value = data.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(f"{name}: must be an integer between {low} and {high}")
    return value


def _server_url(value: object) -> str:
    if not isinstance(value, str):
        raise ConfigError("server.url: required, e.g. http://192.168.64.1:8000")
    parts = urlsplit(value)
    if (
        parts.scheme not in ("http", "https")
        or not parts.netloc
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise ConfigError(f"server.url: expected http(s)://host[:port], got {value!r}")
    return f"{parts.scheme}://{parts.netloc}"


def _read_key(server: Mapping[str, Any], environ: Mapping[str, str]) -> str:
    key = environ.get(ENV_KEY, "").strip()
    if not key:
        key_file = server.get("key_file")
        if not isinstance(key_file, str):
            raise ConfigError(f"no API key: set server.key_file or the {ENV_KEY} variable")
        path = Path(key_file)
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                raise ConfigError(
                    f"{path}: key file permissions {mode:04o} are too open, run chmod 600"
                )
            key = path.read_text().strip()
        except OSError as exc:
            raise ConfigError(f"cannot read key file {path}: {exc.strerror}") from exc
    if not _KEY_PATTERN.match(key):
        raise ConfigError("the API key is malformed (expected <agent id>.<secret>)")
    return key


def _sources(raw: object) -> tuple[Source, ...]:
    if not isinstance(raw, list) or not raw:
        raise ConfigError("at least one [[sources]] entry is required")
    sources: list[Source] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ConfigError("[[sources]] entries must be tables")
        _only_keys("sources", entry, {"path", "source"})
        path, source = entry.get("path"), entry.get("source")
        if not isinstance(path, str) or not Path(path).is_absolute():
            raise ConfigError(f"sources.path: must be an absolute path, got {path!r}")
        if source not in LINUX_SOURCES:
            raise ConfigError(f"sources.source: must be one of {', '.join(LINUX_SOURCES)}")
        if any(existing.path == Path(path) for existing in sources):
            raise ConfigError(f"sources.path: {path} is listed twice")
        sources.append(Source(Path(path), source))
    return tuple(sources)


BACKENDS = ("iptables", "log")


def _response(raw: object) -> ResponseConfig | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ConfigError("[response] must be a table")
    _only_keys(
        "response",
        raw,
        {"backend", "never_block", "poll_interval", "state_file", "max_blocks", "max_ttl_seconds"},
    )
    backend = raw.get("backend")
    if backend not in BACKENDS:
        raise ConfigError(f"response.backend: must be one of {', '.join(BACKENDS)}")
    never = raw.get("never_block")
    if not isinstance(never, list) or not all(isinstance(item, str) for item in never):
        # Mandatory on purpose (an empty list is allowed): whoever enables blocking must decide
        # which addresses (the operator's, monitoring, the office) can never be cut off.
        raise ConfigError("response.never_block: required, a list of addresses or networks")
    try:
        parse_networks(never)
    except ValueError as exc:
        raise ConfigError(f"response.never_block: {exc}") from exc
    poll = raw.get("poll_interval", 5)
    if isinstance(poll, bool) or not isinstance(poll, int | float) or not 1 <= poll <= 300:
        raise ConfigError("response.poll_interval: must be a number of seconds in [1, 300]")
    return ResponseConfig(
        backend=backend,
        never_block=tuple(never),
        poll_interval=float(poll),
        state_file=Path(raw.get("state_file", "/var/lib/sentinel-agent/blocks.json")),
        max_blocks=_int_in(raw, "max_blocks", 100, 1, 10_000),
        max_ttl_seconds=_int_in(raw, "max_ttl_seconds", 86_400, 60, 30 * 86_400),
    )


def load_config(path: Path, environ: Mapping[str, str] | None = None) -> Config:
    environ = os.environ if environ is None else environ
    try:
        data = tomllib.loads(path.read_text())
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc

    _only_keys("config", data, {"server", "agent", "sources", "response"})
    server = data.get("server", {})
    agent = data.get("agent", {})
    _only_keys("server", server, {"url", "key_file", "ca_file"})
    _only_keys(
        "agent", agent, {"state_file", "start_at", "batch_lines", "batch_bytes", "poll_interval"}
    )

    start_at = agent.get("start_at", "end")
    if start_at not in ("end", "beginning"):
        raise ConfigError("start_at: must be 'end' or 'beginning'")
    poll = agent.get("poll_interval", 0.5)
    if isinstance(poll, bool) or not isinstance(poll, int | float) or not 0 < poll <= 60:
        raise ConfigError("poll_interval: must be a number of seconds in ]0, 60]")

    return Config(
        server_url=_server_url(server.get("url")),
        key=_read_key(server, environ),
        sources=_sources(data.get("sources")),
        state_file=Path(agent.get("state_file", "/var/lib/sentinel-agent/state.json")),
        batch_lines=_int_in(agent, "batch_lines", 200, 1, MAX_BATCH_LINES),
        batch_bytes=_int_in(agent, "batch_bytes", 1_048_576, MIN_BATCH_BYTES, MAX_BATCH_BYTES),
        start_at=start_at,
        poll_interval=float(poll),
        ca_file=Path(server["ca_file"]) if "ca_file" in server else None,
        response=_response(data.get("response")),
    )
