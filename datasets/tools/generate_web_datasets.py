"""Writes the Traefik access-log scenarios of the web rules (datasets/web-*/ and the benign web day).

Deterministic: run `python datasets/tools/generate_web_datasets.py` from the repository root and
commit the result. Each line is a realistic subset of Traefik's JSON access-log entry (the
normalizer reads only a few of its fields).
"""

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = datetime(2026, 9, 29, 10, 0, 0, tzinfo=UTC)
HOST = "sentinel.example.org"
BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
SCANNER = "Mozilla/5.0 zgrab/0.x"


def line(
    seconds: float,
    ip: str,
    path: str,
    status: int,
    method: str = "GET",
    agent: str = BROWSER,
    entry: str = "https",
) -> str:
    when = BASE + timedelta(seconds=seconds)
    return json.dumps(
        {
            "ClientAddr": f"{ip}:50000",
            "ClientHost": ip,
            "DownstreamStatus": status,
            "RequestHost": HOST,
            "RequestMethod": method,
            "RequestPath": path,
            "RequestProtocol": "HTTP/2.0",
            "RouterName": "sentinel@docker",
            "StartUTC": when.strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z",
            "entryPointName": entry,
            "request_User-Agent": agent,
        },
        separators=(",", ":"),
    )


def by_time(lines: list[str]) -> list[str]:
    """Chronological order (a log is written as requests arrive), not the order of JSON keys."""
    return sorted(lines, key=lambda entry: json.loads(entry)["StartUTC"])


def write(directory: str, name: str, header: list[str], lines: list[str]) -> None:
    target = ROOT / directory
    target.mkdir(parents=True, exist_ok=True)
    head = ["# source: traefik.access", *header]
    (target / f"{name}.log").write_text("\n".join(head + lines) + "\n")


SWEEP = [
    "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/index.php", "/xmlrpc.php",
    "/server-status", "/backup.sql", "/actuator/health", "/cgi-bin/luci",
]  # fmt: skip
A = "203.0.113.50"
B = "203.0.113.51"


def probe(ip: str, paths: list[str], start: float, gap: float, status: int = 404) -> list[str]:
    return [line(start + i * gap, ip, p, status, agent=SCANNER) for i, p in enumerate(paths)]


def probing() -> None:
    d = "web-path-probing"
    write(d, "attack", ["# expect: 1", "# description: Nine sensitive paths in 16 seconds."],
          probe(A, SWEEP, 0, 2))
    write(d, "attack-spa-answers-200",
          ["# expect: 1", "# description: The app answers 200 to every probe (single-page fallback): still a sweep."],
          probe(A, SWEEP[:6], 0, 3, status=200))
    write(d, "attack-boundary-four",
          ["# expect: 1", "# description: Exactly four distinct sensitive paths in 30 seconds."],
          probe(A, SWEEP[:4], 0, 10))
    write(d, "attack-traversal",
          ["# expect: 1", "# description: Path traversal attempts count as sensitive paths."],
          probe(A, ["/../../etc/passwd", "/a/..%2f..%2fetc/shadow", "/static/%2e%2e/%2e%2e/proc/self/environ",
                    "/download?f=/etc/passwd", "/x/../y/../../boot.ini"], 0, 5))
    write(d, "attack-cooldown",
          ["# expect: 1", "# description: A long sweep raises one alert, not one per path (five-minute cooldown)."],
          probe(A, SWEEP, 0, 2) + probe(A, [f"/.git/{n}" for n in range(12)], 20, 5))
    write(d, "attack-two-sources",
          ["# expect: 2", "# description: Two sources sweeping at once are counted separately."],
          by_time(probe(A, SWEEP[:5], 0, 3) + probe(B, SWEEP[2:8], 1, 3)))
    write(d, "benign-three-paths",
          ["# expect: 0", "# description: Three distinct sensitive paths: one below the threshold."],
          probe(A, SWEEP[:3], 0, 5))
    write(d, "benign-one-path-repeated",
          ["# expect: 0", "# description: A bot hammering /.env thirty times is one path, not a sweep (documented blind spot)."],
          [line(i * 2, A, "/.env", 404, agent=SCANNER) for i in range(30)])
    write(d, "benign-ordinary-404s",
          ["# expect: 0", "# description: Fifteen 404s on ordinary paths (favicon, robots, old links) are not probes."],
          [line(i * 3, A, p, 404) for i, p in enumerate(
              ["/favicon.ico", "/robots.txt", "/apple-touch-icon.png", "/sitemap.xml", "/old-page",
               "/v1/alerts/zzz", "/img/logo.png", "/assets/missing.js", "/favicon.ico", "/robots.txt",
               "/blog", "/about", "/contact", "/apple-touch-icon-precomposed.png", "/humans.txt"])])
    write(d, "benign-lookalikes",
          ["# expect: 0", "# description: Paths that merely contain a sensitive word are not probes (whole segments only)."],
          [line(i * 2, A, p, 404) for i, p in enumerate(
              ["/v1/alerts/environment", "/backup-policy", "/blog/wp-login-tips", "/v1/incidents/console",
               "/docs/the-git-book", "/pma-guide", "/manager-notes"])])
    write(d, "negative-fourth-after-window",
          ["# expect: 0", "# description: Three probes, then a fourth 61 seconds after the first: outside the window."],
          probe(A, SWEEP[:3], 0, 10) + [line(61, A, SWEEP[3], 404, agent=SCANNER)])


def login_failures(ip: str, count: int, start: float, gap: float, status: int = 401) -> list[str]:
    return [line(start + i * gap, ip, "/v1/auth/login", status, method="POST") for i in range(count)]


def login() -> None:
    d = "web-login-bruteforce"
    write(d, "attack", ["# expect: 1", "# description: Twelve failed logins in 22 seconds."],
          login_failures(A, 12, 0, 2))
    write(d, "attack-boundary-ten",
          ["# expect: 1", "# description: Exactly ten failed logins in 45 seconds."],
          login_failures(A, 10, 0, 5))
    write(d, "attack-throttled",
          ["# expect: 1", "# description: Eight 401s then the API's throttle answers 429: all count."],
          login_failures(A, 8, 0, 2) + login_failures(A, 5, 16, 2, status=429))
    write(d, "attack-two-sources",
          ["# expect: 2", "# description: Two addresses guessing at once are counted separately."],
          by_time(login_failures(A, 10, 0, 3) + login_failures(B, 11, 1, 3)))
    write(d, "benign-nine-failures",
          ["# expect: 0", "# description: Nine failed logins in a minute: one below the threshold."],
          login_failures(A, 9, 0, 5))
    write(d, "benign-slow",
          ["# expect: 0", "# description: Fifteen failures spread over five minutes never reach ten in a minute."],
          login_failures(A, 15, 0, 20))
    write(d, "benign-busy-office",
          ["# expect: 0", "# description: Thirty successful logins from one address (a busy office behind one NAT)."],
          [line(i * 2, A, "/v1/auth/login", 200, method="POST") for i in range(30)])
    write(d, "negative-tenth-after-window",
          ["# expect: 0", "# description: Nine failures, then a tenth 61 seconds after the first: outside the window."],
          login_failures(A, 9, 0, 5) + [line(61, A, "/v1/auth/login", 401, method="POST")])


def benign_day() -> None:
    rng = random.Random(20260929)
    lines: list[str] = []
    ips = [f"198.51.100.{n}" for n in range(1, 25)]
    pages = ["/", "/alerts", "/incidents", "/blocks", "/mitre", "/map", "/assets/index.js",
             "/assets/index.css", "/v1/alerts", "/v1/incidents", "/v1/auth/me", "/v1/stats/mitre",
             "/v1/response/blocks", "/healthz"]  # fmt: skip
    t = 0.0
    for _ in range(600):
        t += rng.uniform(1, 90)
        ip = rng.choice(ips)
        r = rng.random()
        if r < 0.80:
            lines.append(line(t, ip, rng.choice(pages), 200))
        elif r < 0.88:
            lines.append(line(t, ip, "/favicon.ico", 404))
        elif r < 0.93:
            lines.append(line(t, ip, "/v1/auth/login", 401, method="POST"))
        elif r < 0.97:
            lines.append(line(t, ip, "/v1/auth/login", 200, method="POST"))
        else:
            lines.append(line(t, ip, rng.choice(SWEEP[:3]), 404, agent=SCANNER))  # a stray probe
    lines = by_time(lines)
    write("_shared", "benign-web-day",
          ["# expect: 0", "# description: An ordinary day on the dashboard (~600 requests): pages, API calls, typos, "
           "the odd stray probe, all below every threshold. No rule may alert.",
           "# Generated by datasets/tools/generate_web_datasets.py (fixed seed): do not edit by hand."],
          lines)


if __name__ == "__main__":
    probing()
    login()
    benign_day()
