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

## `nginx.access`

Accepted by the API, **no normalizer yet**: its lines are dead-lettered (planned with the web rules).
