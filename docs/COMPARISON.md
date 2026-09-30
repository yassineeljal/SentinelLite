# SentinelLite and Wazuh

Wazuh is the obvious open-source comparison: a SIEM/XDR platform with agents, rules mapped to MITRE
ATT&CK, a dashboard and an active-response mechanism. This page says where SentinelLite is different and,
just as important, where it is not in the same league.

**Read this with the right caveats.** It is a design-level comparison written from Wazuh's public
documentation and general knowledge. Wazuh was **not** installed or benchmarked next to SentinelLite, so
there is no side-by-side figure here, and nothing about Wazuh's performance or rule quality is claimed.
Check any Wazuh point against its current documentation before relying on it.

## What SentinelLite is for

One operator, a handful of Linux servers, and the wish to *understand every piece*: a platform small
enough for one person to hold in their head, whose detections are measured and whose automatic response is designed to
be hard to misuse. It is a portfolio-grade, running system, not a replacement for a mature product.

## Where it is deliberately different

| | SentinelLite | Wazuh (as publicly documented) |
|---|---|---|
| Size | About 12,500 lines (8,800 Python backend, 1,600 Python agent with no dependency, 2,100 TypeScript) | A large, mature product with many components and integrations |
| Detection content | 16 rules, each with labelled attack, benign and near-miss scenarios; CI fails if the benchmark drifts | A large ready-made rule and decoder set, maintained by a company and a community |
| Rule format | Strict YAML, an unknown key refuses to load; compared values only, path classes decided in code | XML decoders and rules, very expressive |
| Measurability | Detection rate, false alerts on a benign corpus, and latency are reproducible with one command (`sentinel bench`) | Not assessed here |
| Response | Pull-based: the host's enforcer fetches an action, re-validates the address, applies it, lifts it by itself; dry run by default; audit log append-only | Active response scripts run by the agent on manager instruction |
| Explainability | The risk score lists its factors and the reason for each | Rule levels and descriptions |
| Operating cost | Postgres, Redis, a few small workers | Manager, indexer and dashboard; a heavier footprint |

## Where SentinelLite is not competitive (honestly)

- **Coverage.** Two log sources (SSH auth log, Traefik access log) and Linux only. No file-integrity
  monitoring, no configuration assessment, no vulnerability detection, no cloud or container integrations,
  no Windows or macOS agent, no syscall or process auditing.
- **Scale and availability.** Single instance, no clustering, no high availability, no multi-tenancy.
- **Maturity.** One deployment, weeks of running, no community, no third-party review. The detections are
  measured on datasets written by the same person who wrote the rules, which biases the figures in its
  favour; the live VPS is the only independent check.
- **Threat coverage.** Rules target guessing, scanning, and a few account and privilege changes. Nothing
  models lateral movement, persistence, or exfiltration.

## What was worth learning from it

The interesting engineering is in the seams: a logging feedback loop avoided before it started, a
single-page app that answers 200 to a probe, an oversized request that would have hidden itself, an agent
that must survive a hostile platform, and an outage caused by its own operator that led to the watchdog.
They are written up in [`DEVLOG.md`](DEVLOG.md).

## If you need a real SIEM

Use Wazuh (or another maintained product). If you want to *learn how one works*, or to run something
small that you fully understand on a server you own, this repository is built for that.
