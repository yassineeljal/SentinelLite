# Ingestion API (v1)

Contract between agents and the platform. Implemented in
`backend/src/sentinel_core/api/ingest.py`; agent keys in `sentinel_core/auth/agent_keys.py`.

## Authentication

Every request carries the agent's key:

```
Authorization: Bearer <agent_uuid>.<secret>
```

- The secret is 256 bits of randomness (`secrets.token_urlsafe(32)`). The server stores only its
  SHA-256 hash and compares in constant time (`hmac.compare_digest`). A fast hash is appropriate
  here because the secret is random, unlike a human password.
- The key is shown **once**, when the agent is created. It is revocable (a revoked agent is
  treated as unknown).
- The agent identity is derived from the key. A request body containing `agent_id` (or any other
  unknown field) is rejected with `422`: an agent can never write events on behalf of another one.
- Unknown agent, wrong secret, revoked agent, malformed header: **the same `401` answer**, so the
  API does not reveal whether an agent id exists.
- Fail closed: until an agent registry is configured, every request is `401`.

## `POST /v1/ingest`

```json
{
  "source": "linux.auth",
  "lines": [
    { "origin": "1835201:48213", "line": "2026-09-24T15:04:05+00:00 host sshd[812]: Failed password for root from 203.0.113.7 port 51234 ssh2" }
  ]
}
```

| Field | Rules |
|---|---|
| `source` | One of `linux.auth`, `nginx.access`, `windows.security`, `windows.sysmon` |
| `lines` | 1 to 500 items |
| `lines[].origin` | 1–128 chars. Stable position of the line in its source (e.g. `<inode>:<byte offset>`). Together with the agent and source it forms the idempotency key, so **re-sending a batch after a failure never creates duplicates** |
| `lines[].line` | Up to 8192 chars, the raw line, unmodified |

The server adds `received_at` (its own clock, never trusted from the agent). Timestamps inside the
line are interpreted by the normalizer, not by the API.

### Responses

| Status | Meaning | Agent behaviour |
|---|---|---|
| `202` `{"accepted": n}` | Batch queued (all lines or none) | Advance the file offset |
| `401` | Missing/invalid credentials | Stop and alert the operator; do not retry blindly |
| `413` | Body over the limit (default 8 MiB) | Split the batch |
| `422` | Invalid payload | Fix the agent (bug); drop or quarantine the batch |
| `429` + `Retry-After` | Queue above its high watermark | Wait `Retry-After` seconds, retry from the disk buffer |
| `503` | Queue unreachable | Retry with exponential backoff from the disk buffer |

`202` means *queued*, not *processed*: normalization and detection are asynchronous.

## Limits and their reason

| Limit | Default | Setting | Why |
|---|---|---|---|
| Lines per batch | 500 | — | Bounds per-request work |
| Line length | 8192 chars | — | Bounds memory and log-injection payloads |
| Request body | 8 MiB | `SENTINEL_INGEST_MAX_BODY_BYTES` | FastAPI buffers the body before validation; the limit is enforced first, both on `Content-Length` and on chunked bodies |
| Queue high watermark | 100 000 entries | `SENTINEL_RAW_STREAM_HIGH_WATERMARK` | Explicit backpressure instead of silently trimming unprocessed events |

## Queue format (`events.raw`)

One Redis Stream entry per line, single field `data` holding a `RawLog` as JSON
(`agent_id`, `source`, `origin`, `line`, `received_at`). A batch is written in one `MULTI/EXEC`
transaction. Consumers (the normalizer) read through a consumer group and must delete entries
after acknowledging them, otherwise the stream length eventually reaches the watermark and the API
answers `429`.

## Not implemented yet

- Persistent agent registry (Postgres) and agent creation/revocation CLI — next step.
- Per-agent rate limiting.
- The `GET /v1/agents/me/actions` polling endpoint used by the responder.
