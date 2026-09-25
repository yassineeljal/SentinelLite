# Linux agent

`agents/linux/` — follows log files on a monitored host and ships their lines to the ingestion API
([`INGESTION_API.md`](INGESTION_API.md)). Standard library only, Python ≥ 3.11 (Ubuntu 24.04 ships
3.12). Design principle: **dumb agent, smart server** — it tags the source and ships raw lines; all
parsing happens on the platform.

## What it guarantees

- **At-least-once delivery, no loss on restart.** A read position is stored only *after* the server
  answered `202` for the lines before it. A crash, a kill or a network outage therefore re-sends,
  never skips. The state file is written atomically (temporary file, fsync, rename).
- **Repeats are harmless.** Each line's `origin` is `<inode>:<byte offset of the line start>`; with the
  agent and the line content it forms the server's idempotency key, so re-sent lines create no
  duplicate event and no duplicate alert.
- **It never gets stuck, and never silently discards a log.**
  - `422` / `413`: the batch is split until the offending line is alone; only that line is dropped
    (logged with its origin).
  - After **10 refused lines in a row** it stops (exit 3): a systematic refusal (contract mismatch
    after an upgrade, say) must not eat the whole log.
- **It survives the network.** `503`, timeouts and refused connections are retried forever with
  capped exponential backoff (1 s … 60 s) and jitter; `429` waits `Retry-After`. Lines stay in the log
  file meanwhile: memory holds one batch.
- **A refused key stops it** (`401`, exit 2): a revoked key needs a human, not a retry loop. The
  refused lines are *not* acknowledged, so they are sent once a new key is installed.

## Log handling

| Situation | Behaviour |
|---|---|
| Incomplete last line | Waited for; shipped once its newline is written |
| `logrotate` rename | The old file stays open until drained, then the new file is followed from its start |
| File deleted and recreated (even with the same inode number) | Detected (link count 0); old data drained first |
| `copytruncate` | Detected (file smaller than the read position or head changed): restart from the top. Lines written between the last read and the truncation are lost |
| Agent down during a rotation | The rotated file (`auth.log.1`) is found by its saved inode; compressed rotations (`.gz`…) are not followed |
| Inode number recycled across restarts | A fingerprint of the first 256 bytes, saved once the position is past them, tells the files apart |
| Invalid UTF-8 | Replaced by U+FFFD |
| NUL bytes | Escaped as `\x00` (PostgreSQL cannot store them) |
| Line longer than 8192 characters | Truncated with a `…[truncated]` marker (the API would refuse it), the rest of the line is skipped |
| Blank lines | Not shipped |
| File missing | Waited for; followed from its start when it appears |

A file with no saved position starts at its **end** (`start_at = "end"`) so that installing the agent
does not replay a year of history; use `"beginning"` to ship existing content.

## Install (Ubuntu / Debian)

```bash
# On a development machine: build the wheel
cd agents/linux && uv build                       # dist/sentinel_agent-0.1.0-py3-none-any.whl

# On the monitored host
sudo useradd --system --home-dir /var/lib/sentinel-agent --shell /usr/sbin/nologin sentinel-agent
sudo usermod -aG adm sentinel-agent               # read /var/log/auth.log
sudo python3 -m venv /opt/sentinel-agent
sudo /opt/sentinel-agent/bin/pip install sentinel_agent-0.1.0-py3-none-any.whl
sudo install -d -m 0750 -o root -g sentinel-agent /etc/sentinel-agent
sudo install -m 0640 -g sentinel-agent agents/linux/deploy/agent.toml.example /etc/sentinel-agent/agent.toml
sudo editor /etc/sentinel-agent/agent.toml        # server url, sources

# On the platform: register the agent, then put the printed key on the host
docker compose exec api sentinel agents create --name target-linux-01 --os linux
printf '%s' '<key>' | sudo tee /etc/sentinel-agent/key >/dev/null
sudo chown sentinel-agent: /etc/sentinel-agent/key && sudo chmod 600 /etc/sentinel-agent/key

sudo install -m 0644 agents/linux/deploy/sentinel-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now sentinel-agent
journalctl -u sentinel-agent -f
```

> The systemd unit (hardened: `NoNewPrivileges`, `ProtectSystem=strict`, restricted address families,
> empty capability set…) was validated on **Ubuntu 24.04.5 arm64** on 2026-09-25: it starts, reads
> `/var/log/auth.log` through the `adm` group and ships to the API; `systemd-analyze security
> sentinel-agent` reports an exposure level of **4.2 (OK)**. Other distributions are untested.
>
> **Shortcut:** `lab/scripts/deploy-agent.sh` does all of the above from the platform host over SSH
> (build the wheel, register the agent, copy the key to a private file, install, start), see
> [`lab/README.md`](../lab/README.md).

## Run by hand

```bash
sentinel-agent --config agent.toml            # follow mode (Ctrl-C / SIGTERM: finish and exit)
sentinel-agent --config agent.toml --once     # ship what is available, then exit
sentinel-agent --config agent.toml --once --retries 2   # give up after 2 retries if unreachable
sentinel-agent --config agent.toml -v         # debug logging
```

| Exit code | Meaning |
|---|---|
| 0 | Normal stop |
| 1 | Configuration error (message on stderr, no traceback) |
| 2 | The server refused the key (unknown or revoked): create a new one |
| 3 | The server refuses the log systematically: check versions / contract |
| 4 | Server unreachable (`--once` only) |

## Configuration

See [`agents/linux/deploy/agent.toml.example`](../agents/linux/deploy/agent.toml.example). Everything is
validated at startup and **unknown keys are refused**, so a typo fails loudly instead of changing
behaviour silently. The API key is **never** read from the configuration file: only from a private
file (`server.key_file`, refused if group/other-readable) or the `SENTINEL_AGENT_KEY` variable. It is
never logged and is hidden from `repr()`.

## Security notes

- **The agent is semi-trusted by the platform** (ADR 21): its key lives on a monitored host, so a
  compromised host can send arbitrary lines. The server bounds the impact (per-agent detection state,
  timestamp clamp, neutralised input). The agent does its part: it never follows redirects (the key
  would leak to another host), verifies TLS by default (`ca_file` for a private CA, no way to disable
  verification), and keeps no secret in its configuration.
- **Plaintext transport.** `http://` to a non-loopback address is accepted (isolated lab) but logs a
  warning: log lines and the key travel unencrypted. Use `https://` anywhere else.
- **Log content leaves the host.** Whatever is in the followed files is sent: choose the sources.

## Limits (v0.1)

- Linux sources only: `linux.auth` (parsed by the platform) and `nginx.access` (accepted by the API
  but **not normalized yet**: its lines are dead-lettered until that normalizer exists).
- Polling (0.5 s), no inotify. Compressed rotated files are not followed. `copytruncate` can lose
  the few lines written between the last read and the truncation.
- No response channel yet: the agent does not fetch or execute actions (blocking an IP is planned
  for M5, by *pull*, so that no port is opened on the host).
- No TLS client certificates, no proxy support.
- The systemd unit is validated on Ubuntu 24.04 only.
