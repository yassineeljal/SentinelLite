"""Normalizer for Traefik's JSON access log (`--accesslog.format=json`), one request per line.

An oversized request (a path of several kilobytes) makes a line the agent has to truncate, which
breaks the JSON. Such a line is not dropped, that would let an attacker hide by lengthening the
path: the fields Traefik writes before the path are recovered, the receipt time stands in for the
lost timestamp, and the request counts as a probe (`truncated: true`, `path_class: sensitive`).

Only requests that can matter to a detection become events: a request for a path that scanners
look for (`/.env`, `/wp-login.php`...) whatever the answer, and every request answered with an
error (4xx/5xx). An ordinary successful request carries no security signal and is not stored.

The path class is decided here, in code, because rules can only compare values: `extra.path_class`
is `sensitive` for a probe path, `login` for the dashboard's login endpoint, else `other`. The
status is not enough to tell a probe: a single-page app answers 200 to any unknown path, so a
scanner looking for `/.env` gets a "success".
"""

import json
import re
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any

from sentinel_core.normalizers.base import ParseError, RawLog, make_event_id
from sentinel_core.schema.event import Action, Category, Event, Outcome, Source

MAX_PATH = 512
MAX_AGENT = 256
LOGIN_PATH = "/v1/auth/login"

# Exact paths and first path segments that are probed by scanners and worms. Compared on whole
# segments, never as substrings: `/v1/alerts/environment` is not `/.env`.
SENSITIVE_PREFIXES = frozenset(
    {
        # Dotfiles and version control
        ".env", ".git", ".svn", ".hg", ".aws", ".ssh", ".docker", ".vscode", ".ds_store",
        ".npmrc", ".htaccess",
        # WordPress and PHP applications
        "wp-login.php", "wp-admin", "wp-content", "wp-includes", "wp-config.php", "xmlrpc.php",
        "phpmyadmin", "pma", "myadmin", "phpinfo.php", "info.php", "adminer.php", "config.php",
        "configuration.php", "eval-stdin.php", "shell.php", "cmd.php", "c99.php",
        # Servers, consoles and frameworks
        "cgi-bin", "actuator", "server-status", "manager", "boaform", "hnap1", "solr", "jenkins",
        "console", "vendor", "telescope", "_ignition", "owa", "autodiscover", "geoserver", "struts",
        # Backups, dumps and keys
        "backup", "backups", "dump.sql", "db.sql", "database.sql", "id_rsa", "credentials",
        ".htpasswd",
    }
)  # fmt: skip
SENSITIVE_SUFFIXES = (".sql", ".bak", ".old", ".swp", ".tar.gz", ".zip", ".pem", ".key")
TRAVERSAL = ("..", "%2e%2e", "%252e", "\\x", "/etc/passwd", "/proc/self")


def path_class(path: str) -> str:
    lowered = path.lower()
    if lowered == LOGIN_PATH:
        return "login"
    if any(mark in lowered for mark in TRAVERSAL):
        return "sensitive"
    segments = [part for part in lowered.split("/") if part]
    if segments and segments[0] in SENSITIVE_PREFIXES:
        return "sensitive"
    if segments and lowered.endswith(SENSITIVE_SUFFIXES):
        return "sensitive"
    return "other"


TRUNCATION_SUFFIX = "…[truncated]"  # what the agent appends when it cuts a line (tailer.py)
_SALVAGE = {
    "host": re.compile(r'"ClientHost"\s*:\s*"([^"]{0,64})"'),
    "status": re.compile(r'"DownstreamStatus"\s*:\s*(\d{3})'),
    "request_host": re.compile(r'"RequestHost"\s*:\s*"([^"]{0,255})"'),
    "method": re.compile(r'"RequestMethod"\s*:\s*"([^"]{0,16})"'),
    "path": re.compile(r'"RequestPath"\s*:\s*"((?:[^"\\]|\\.)*)'),  # may run to the cut
}


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ParseError("missing StartUTC")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ParseError(f"bad StartUTC: {value[:40]!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _text(document: dict[str, Any], key: str, limit: int) -> str:
    value = document.get(key, "")
    return value[:limit] if isinstance(value, str) else ""


class TraefikAccessNormalizer:
    source = Source.TRAEFIK_ACCESS

    def _salvage(self, raw: RawLog) -> Event:
        found = {name: pattern.search(raw.line) for name, pattern in _SALVAGE.items()}
        if not (found["host"] and found["status"] and found["path"]):
            raise ParseError("truncated line without a client, a status and a path")
        try:
            src_ip = ip_address(found["host"][1])
        except ValueError:
            src_ip = None
        status = int(found["status"][1])
        return Event(
            event_id=make_event_id(raw),
            ts=raw.received_at,  # the real timestamp is after the cut
            received_at=raw.received_at,
            agent_id=raw.agent_id,
            host=(found["request_host"][1] if found["request_host"] else "") or "unknown",
            source=self.source,
            category=Category.WEB,
            action=Action.HTTP_REQUEST,
            outcome=Outcome.FAILURE if status >= 400 else Outcome.SUCCESS,
            severity=30,
            src_ip=src_ip,
            dst_port=None,
            user_name=None,
            raw=raw.line,
            extra={
                "method": found["method"][1] if found["method"] else "",
                "path": found["path"][1][:MAX_PATH],
                "path_class": "sensitive",
                "status": status,
                "user_agent": "",
                "truncated": True,
            },
        )

    def normalize(self, raw: RawLog) -> Event | None:
        try:
            document = json.loads(raw.line)
        except ValueError as exc:
            if raw.line.endswith(TRUNCATION_SUFFIX):
                return self._salvage(raw)
            raise ParseError("line is not JSON") from exc
        if not isinstance(document, dict) or "RequestPath" not in document:
            raise ParseError("not a Traefik access log entry")

        status = document.get("DownstreamStatus")
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
            raise ParseError("missing or invalid DownstreamStatus")
        path = _text(document, "RequestPath", MAX_PATH)
        kind = path_class(path)
        if kind == "other" and status < 400:
            return None  # an ordinary request that worked: no security signal

        try:
            src_ip = ip_address(_text(document, "ClientHost", 64))
        except ValueError:
            src_ip = None
        entry = _text(document, "entryPointName", 16)
        outcome = Outcome.FAILURE if status >= 400 else Outcome.SUCCESS
        return Event(
            event_id=make_event_id(raw),
            ts=_timestamp(document.get("StartUTC")),
            received_at=raw.received_at,
            agent_id=raw.agent_id,
            host=_text(document, "RequestHost", 255) or "unknown",
            source=self.source,
            category=Category.WEB,
            action=Action.HTTP_REQUEST,
            outcome=outcome,
            severity=30 if kind == "sensitive" else 10,
            src_ip=src_ip,
            dst_port=443 if entry == "https" else 80 if entry == "http" else None,
            user_name=None,
            raw=raw.line,
            extra={
                "method": _text(document, "RequestMethod", 16),
                "path": path,
                "path_class": kind,
                "status": status,
                "user_agent": _text(document, "request_User-Agent", MAX_AGENT),
            },
        )
