# Event catalogue

What each normalizer produces, i.e. what rules can match on ([`DETECTION.md`](DETECTION.md)). The common
schema is in [`ARCHITECTURE.md`](ARCHITECTURE.md) §6; source-specific data lives in `extra` and is
addressed as `extra.<key>` in rules.

## `linux.auth` (`/var/log/auth.log`)

Formats were **captured from Ubuntu 24.04** and are pinned by tests on real lines
(`backend/tests/normalizers/data/`). Anything not listed is well-formed noise: it produces no event
and, importantly, is **not** a dead letter (only lines that are not syslog at all are).

| Message (process) | `action` | `category` / `outcome` | `user_name` | `src_ip` | `extra` |
|---|---|---|---|---|---|
| `Failed password for [invalid user] U from IP port P` (sshd) | `login_failed` | authentication / failure | U | IP | `method`, `invalid_user`, `src_port` |
| `Accepted <method> for U from IP port P` (sshd) | `login_success` | authentication / success | U | IP | `method`, `src_port` |
| `Invalid user U from IP [port P]` (sshd) | `invalid_user` | authentication / failure | U | IP | `src_port` |
| `<actor> : [TTY=t ;] PWD=d ; USER=target ; COMMAND=cmd` (sudo) | `sudo_command` | process / success | actor | – | `target_user`, `command`, `executable`, `pwd`, `tty`?, `ambiguous`? |
| `<actor> : <reason> ; … USER=… ; COMMAND=…` (sudo) | `sudo_failed` | authentication / failure | actor | – | `reason`, `attempts`?, `detail`?, plus the fields above |
| `new user: name=N, UID=…, GID=…, home=…, shell=…, from=…` (useradd) | `account_created` | iam / success | N | – | `uid`, `gid`, `home`, `shell`, `from` |
| `add 'U' to group 'G'` (usermod) | `group_member_added` | iam / success | U | – | `group`, `tool` = `usermod` |
| `user U added by A to group G` (gpasswd) | `group_member_added` | iam / success | U | – | `group`, `tool` = `gpasswd`, `added_by` |

`sudo_failed` reasons: `user_not_in_sudoers`, `command_not_allowed`, `password_required`,
`incorrect_password` (with `attempts`), and `other` (unknown refusal text kept in `detail`: an
unknown message before the fields means sudo refused, it is never counted as a success).

### Deliberate choices, all learned from the real capture

- **One event per operation.** A sudo failure writes three PAM lines (`authentication failure`,
  `conversation failed`, `could not identify password`) *and* a summary line: only the summary is an
  event. `usermod` writes `add 'u' to group 'g'` and again `add 'u' to shadow group 'g'`: only the
  first. `useradd` also writes `new group`: ignored. Counting them all would multiply alerts by 2–4.
- **Optional fields.** sudo prints no `TTY=` outside a terminal and pads the user name with a variable
  number of spaces.
- **Parenthesised process names** (`(systemd)`, `(sd-pam)`, from systemd user managers) are well-formed
  lines. They were first rejected as malformed and would have filled the dead-letter table.
- **The sudo line is ambiguous by construction.** `PWD=` and `COMMAND=` are controlled by the user, so
  a line can contain fake `USER=… ; COMMAND=…` segments *before* the real one (a crafted directory
  name) or *after* it (arguments). The real segment cannot be told apart from the text, so the choice is
  conservative: a `root` segment wins over the others and, among root segments, one that runs a shell
  wins. A decoy can make an event look **more** sensitive, never hide a root shell. The event carries
  `ambiguous: true` whenever several segments were found. The actor is always the first token of
  the message. Long commands are cut to 2048 characters.

### Not modelled yet

`su` (`FAILED SU`, `(to root) …`), `passwd` (password changes), `groupadd`, PAM authentication
failures outside sudo, sshd disconnects and pre-auth closes.

## `traefik.access` (Traefik's JSON access log)

The web source of the VPS deployment: the reverse proxy in front of the dashboard writes one JSON
object per request (`--accesslog.format=json`, see OPERATIONS.md). Category `web`, action
`http_request`. Normalizer: `normalizers/traefik_access.py`.

| Field | From |
|---|---|
| `ts` | `StartUTC` (nanoseconds are accepted) |
| `src_ip` | `ClientHost` (kept as `null` when it is not an address) |
| `host` | `RequestHost` |
| `dst_port` | 443 for the `https` entry point, 80 for `http` |
| `outcome` | `failure` for a status of 400 and above, else `success` |
| `severity` | 30 for a sensitive path, else 10 |
| `extra.method`, `extra.path` (cut at 512), `extra.status`, `extra.user_agent` (cut at 256) | the request |
| `extra.path_class` | `sensitive`, `login` or `other`, decided by the normalizer |

**Deliberate choices**

- **Only requests that can matter are events**: a probe path whatever the answer, the login endpoint,
  and every request answered with an error. An ordinary request that worked is dropped by the
  normalizer (`None`, not dead-lettered): no security signal, and it would only fill the database.
- **The path class is computed in code**, because rules can only compare values. A probe path is one
  whose first segment is a known target (`.env`, `.git`, `wp-login.php`, `phpmyadmin`, `cgi-bin`...),
  a sensitive file extension (`.sql`, `.bak`, `.pem`...), or a traversal (`..`, `%2e%2e`,
  `/etc/passwd`). Whole segments only: `/v1/alerts/environment` and `/backup-policy` are not probes.
- **The status does not decide.** A single-page app answers 200 to any unknown path, so a scanner
  looking for `/.env` is told "success"; the probe is flagged regardless.
- **An oversized request is not lost.** A path of several kilobytes makes the agent truncate the line
  (8192 characters), which breaks the JSON. Rather than dead-lettering it (an attacker could hide by
  lengthening the path), the normalizer recovers the client, status, host, method and the start of the
  path, uses the receipt time as `ts`, and marks it `extra.truncated: true`, `path_class: sensitive`.
- **The agent's own traffic is not logged** (a router with the access log off, see OPERATIONS.md),
  otherwise shipping a line would create the next line, forever.

## `nginx.access`

Accepted by the API, **no normalizer**: its lines are dead-lettered. Nothing ships it on the VPS
(the proxy is Traefik); the name is kept for a future Nginx deployment.
