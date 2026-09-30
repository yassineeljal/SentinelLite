# Three-minute demo

A walkthrough that uses only what exists and is safe to run against your own deployment (here the public
VPS, `https://sentinel.apps.auditflow.ca`). Nothing below attacks a machine that is not yours. The
responder stays in `dry_run` unless you turned it on, so the demo blocks nothing.

Prepare: sign in to the dashboard as an admin in one window, keep a terminal on the platform host and the
Discord channel next to it.

## 0:00 — What it is (20 s)

"A small SIEM for Linux servers. Agents ship logs, the server normalizes and detects, everything is mapped
to MITRE ATT&CK, and there is a guarded automatic response. It monitors the server it runs on."
Show the README's numbers table: 16 rules, 67/67 attacks, 0 false alerts on 1 050 benign events, and the
fact that CI fails if that drifts.

## 0:20 — A scanner arrives (60 s)

From any shell, sweep the public URL the way a scanner would, then guess the login:

```bash
H=https://sentinel.apps.auditflow.ca
for p in /.env /.git/config /wp-login.php /phpmyadmin/index.php /xmlrpc.php /backup.sql; do
  curl -s -o /dev/null -A "demo-scanner" $H$p; done
for i in $(seq 1 12); do
  curl -s -o /dev/null -X POST -H 'Content-Type: application/json' \
    -d '{"email":"nobody@example.com","password":"wrong"}' $H/v1/auth/login; done
```

Within a second, in the dashboard **Alerts** page: `web-path-probing` (T1595.002) and
`web-login-bruteforce` (T1110). Open one: the evidence lines, the ATT&CK technique, the source address, the
risk factors with the reason for each. Point out that the app answered `200` to every probe (a
single-page app does that): the rule looks at the path, not the status.

## 1:20 — Why you can trust it (40 s)

- Open `docs/BENCHMARK.md` or run `cd backend && uv run sentinel bench`: every rule has attack, benign and
  near-miss scenarios, e.g. `web-path-probing/negative-fourth-after-window` (the fourth probe comes 61 s
  after the first: it must *not* fire).
- Show a rule file, `rules/web-path-probing.yaml`: plain YAML, strict validation, an unknown key refuses to
  load.
- Mention the real SSH attack measured at 7.4 s from `hydra` to alert (`lab/README.md`).

## 2:00 — Response, with brakes (40 s)

Open the **Blocks** page. Explain, in this order: dry run by default; only sweeping/guessing rules; public
addresses only; the allowlist always wins; a mandatory TTL; a rate cap; an append-only audit log. Then the
architecture point: the platform never pushes a rule, the host's own **enforcer** pulls the action, checks
the address again, applies it to `iptables`, and lifts it by itself at the end time.

```bash
sudo docker exec sentinellite-api-1 sentinel blocks          # what was (or would be) blocked
sudo docker exec sentinellite-api-1 sentinel unblock <ip>    # a false positive, undone in seconds
```

## 2:40 — Someone watches the watcher (20 s)

```bash
sudo systemctl stop sentinel-agent      # the log agent dies...
# ...and within about five minutes, on Discord: "SILENT agent vps-01 has not reported"
sudo systemctl start sentinel-agent     # ...and "agent vps-01 is reporting again"
sudo docker exec sentinellite-api-1 sentinel report --output /tmp/report.html   # a printable report
```

Closing line: "It caught its own failure the way it catches an attacker: it told someone." (This is not a
figure of speech: the log agent was once down for two hours and nobody knew, which is why the watchdog
exists. The story is in the devlog.)

## If something is not there

- No alert: check the agent is reporting (`sentinel agents list` shows `last seen`) and that the proxy
  access log is on ([OPERATIONS.md](OPERATIONS.md), "Web access logs").
- The responder is off by default: without `SENTINEL_RESPONDER_ENABLED=true` there is nothing on the
  Blocks page, which is fine for the demo of detection.
