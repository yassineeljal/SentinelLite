# Dashboard

Who can see alerts, how they prove who they are, and the web app they see them in. Backend code in
`backend/src/sentinel_core/auth/` (users, passwords, sessions) and `backend/src/sentinel_core/api/`
(`auth.py`, `alerts.py`); frontend in `frontend/` (React + Vite + TS, ADR 9, its own
[`frontend/README.md`](../frontend/README.md)). Not built yet: the map, incidents, the MITRE
ATT&CK chart, 2FA.

## Accounts

**No self-registration.** The only way to get a dashboard account is `sentinel users create`
(an admin with shell access to the platform):

```bash
docker compose exec api sentinel users create --email alice@example.com --role analyst
# Password:            (typed, not echoed)
# Confirm password:
```

- **Roles**: `analyst` (read alerts; more views arrive with the rest of the dashboard) and `admin`
  (also manages users, later: rules, response). Enforced by a `CHECK` constraint in the database
  and validated again in code — the same "typo can't silently disable a check" principle as rules
  (`DETECTION.md`).
- **Passwords**: hashed with Argon2id (`argon2-cffi`, library defaults — no custom cost parameters
  to get subtly wrong), 12-1024 characters. Never logged, never returned by any endpoint.
- `email` is a **login identifier, not a deliverable address**: syntax is checked (one `@`, a dot
  after it, no whitespace) but reserved/internal TLDs (`.local`, `.test`, `.internal`...) are
  accepted on purpose — a self-hosted lab has no reason to own a real domain. Stored lowercased, so
  `Alice@Example.com` and `alice@example.com` are the same account.
- `sentinel users list` never shows a password hash; `sentinel users revoke <id>` deactivates the
  account **and deletes every one of its sessions** — an admin locking out a colleague, or
  offboarding, must not leave a live session behind.

## Sessions

A session is a random 256-bit token, shown once at login; only its SHA-256 hash is stored
(`user_sessions.id`), the same pattern as an agent's API key. It travels as a cookie
(`sl_session`), not a header the frontend has to attach itself:

| Attribute | Value | Why |
|---|---|---|
| `HttpOnly` | always | Client-side script (and any XSS) can never read the cookie |
| `SameSite` | `Strict` | No request from another site's page ever carries it: this is the CSRF defence, on purpose instead of a separate token (ADR 34) |
| `Secure` | on by default, `SENTINEL_SESSION_COOKIE_SECURE=false` to turn off | Real browsers (and `httpx`, and Python's `http.cookiejar`) never resend a `Secure` cookie over plain HTTP: needed for the lab, never for a network-reachable deployment |
| Lifetime | `SENTINEL_SESSION_TTL_HOURS` (default 8h), enforced server-side | A stolen cookie stops working on its own after a work day |

`POST /v1/auth/login` (email + password) sets the cookie; `POST /v1/auth/logout` deletes the
session and clears it; `GET /v1/auth/me` returns the current user or `401`. A wrong password and an
unknown email give the **exact same** generic `401`, in the same amount of work either way (a
dummy hash is verified against on an unknown email — see `ingest.py`'s `_DUMMY_HASH` for the same
reasoning with agent keys): neither timing nor the response reveals which accounts exist.

## The alerts API

Two routes, both requiring a valid session:

- `GET /v1/alerts?limit=&rule=` — the list, same fields `sentinel alerts list` prints.
- `GET /v1/alerts/{alert_id_prefix}` — one alert's full detail: MITRE techniques, the group it was
  raised for, its evidence events (oldest first, with the raw log line), detection latency in
  milliseconds, and the enrichment/risk JSON exactly as `set_enrichment` stored them. Accepts a
  hexadecimal id prefix (>= 6 chars), like the CLI; an ambiguous prefix or a malformed one is `400`,
  an unknown id is `404`. This is the same information `sentinel alerts show` prints — the CLI and
  the dashboard are two views of one query (`db/alerts.get_alert`), not two implementations.

Every future dashboard route is added to routers that depend on the same `authenticate_user`, so
nothing is reachable by accident before it has been decided to be.

## The frontend

`frontend/` is a small single-page app: a login page, an alert list (auto-refreshing every 15 s,
filterable by rule id, each row linking to its detail page), and an alert detail page (MITRE
techniques, when/who/where, the risk breakdown with every factor's reason, location and
reputation, the evidence table) — behind a session-aware router (`ProtectedRoute` redirects to
`/login` when `GET /v1/auth/me` says there is no session). Nothing here is dashboard-specific
framework code beyond what `api/client.ts` and `auth/AuthContext.tsx` need: no state management
library, no component kit — the surface is still small enough that plain React + `fetch` is the
simplest thing that works, and will be revisited if that stops being true.

**Same origin, on purpose** (ADR 35): the API serves the built app directly (a catch-all route
falls back to `index.html` for client-routed paths like `/alerts`, so a hard refresh or a pasted
link still works), and `vite.config.ts` proxies `/v1` to the backend in dev for the same reason —
neither CORS nor a laxer `SameSite` is ever needed. `deploy/Dockerfile` builds `frontend/dist` in
its own stage and copies it into the final image; `SENTINEL_STATIC_DIR` (baked into the image) is
what tells the API to serve it. Run `npm run dev` (proxies to a backend on `:8000`) or
`npm run build && npm run preview` locally; `npm test`/`typecheck`/`lint`/`format:check` are the
same checks CI runs.

## Not done yet

- **The rest of the dashboard**: map, incidents, an aggregate MITRE ATT&CK chart (the detail page shows one alert's own techniques, not a fleet-wide view).
- **2FA (TOTP)**: planned, not built. `role` RBAC beyond "admin can manage users" (rules, response,
  agents) arrives with the routes it gates.
- **No account lockout** after repeated failed logins yet: a determined attacker is slowed only by
  Argon2's cost. A brute force against the dashboard is exactly the kind of thing `ssh-bruteforce`
  detects in spirit; a matching `dashboard-login-bruteforce`-style rule, or a Redis-backed lockout
  like the reputation service's circuit breaker, is a natural next step.
