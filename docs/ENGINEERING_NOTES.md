# Engineering notes

Bugs and design points that came from *running* SentinelLite rather than from writing it. Each is recorded
in more detail, with its date, in the [devlog](DEVLOG.md).

- **Hardening blinded two rules.** Deployed on a public VPS that only accepts SSH keys, the dashboard stayed
  empty while the server was probed all day: `sshd` no longer logs `Failed password`, so the brute-force
  rule could not fire, and the enumeration rule ignores one name tried many times. A new rule
  (`ssh-invalid-user-flood`) now covers it, threshold chosen against the existing benign data.
- **A logging feedback loop, caught before it started.** The agents reach the API through the same proxy
  whose access log they ship: enabling that log would have made every shipped batch create the next line,
  forever. A dedicated router keeps the agents' own requests out of the log.
- **A single-page app answers 200 to `/.env`.** So the web probe rule classifies the *path* (whole
  segments: `/v1/alerts/environment` is not `/.env`), never the status. And an oversized path used to make
  the agent truncate the line, break the JSON and land the request in the dead letters, invisible to every
  rule: it is now recovered and treated as a probe.
- **A shared Docker network answered to the wrong name.** The API, attached to the platform's network and
  to a reverse proxy's, resolved `postgres` to *another stack's* database. Found by resolving the name
  from inside the container, fixed with unique aliases.
- **`ipaddress.is_global` is not "safe to block".** A test showed multicast (`224.0.0.1`) reported as
  global, and `::ffff:10.0.0.1` must be judged as the private IPv4 it wraps.
- **Tests could not have found this one.** The first real start of the enforcer failed: a root process
  limited to `CAP_NET_ADMIN` cannot read a `0600` key file of another user. And the faulty first unit
  also took ownership of the log agent's state directory and stopped it for 2 h 20 without a word,
  which is why the watchdog exists.
- One stream, one consumer group; attacker-controlled text is treated as hostile everywhere (a user name
  cannot spoof the source IP, terminal output and reports are escaped, untrusted values are cut before
  they reach the audit log).
