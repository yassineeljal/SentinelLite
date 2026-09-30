# Dashboard

Who can see alerts, how they prove who they are, and the web app they see them in. Backend code in
`backend/src/sentinel_core/auth/` (users, passwords, sessions) and `backend/src/sentinel_core/api/`
(`auth.py`, `mfa.py`, `alerts.py`, `incidents.py`); frontend in `frontend/` (React + Vite + TS, ADR 9, its own
[`frontend/README.md`](../frontend/README.md)). Includes alerts, MITRE coverage, the source-location
map, incident triage and optional per-account TOTP two-factor authentication.

## Accounts

**No self-registration.** The only way to get a dashboard account is `sentinel users create`
(an admin with shell access to the platform):

```bash
docker compose exec api sentinel users create --email alice@example.com --role analyst
# Password:            (typed, not echoed)
# Confirm password:
```

- **Roles**: `analyst` (read alerts and manage shared incidents) and `admin`
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

`POST /v1/auth/login` accepts `email`, `password`, and an optional `code`. Accounts with 2FA
require an unused authenticator or recovery code along with the password; the server issues no
session until both pass. Unknown users, wrong passwords, missing codes and invalid/replayed codes
share one generic 401. Unknown users still incur an Argon2 verification against a dummy hash.
Argon2 verification runs off the event loop, with at most two verifications running concurrently per API process.
`POST /v1/auth/logout` deletes the session; `GET /v1/auth/me` returns the current user or 401.
Successful authentication/settings responses carry `Cache-Control: no-store`.

## Authentication attempt limits

Postgres-backed atomic counters apply before password verification: **10 attempts per normalized
login identifier and 50 per source address, per 5-minute fixed window** by default. All attempts
count, including successful logins; success cannot reset the budget. Unknown identifiers get the
same limit as real accounts. Once exhausted, the endpoint returns 429 with a `Retry-After` header
and a readable delay. Blocked attempts do not extend the window. MFA management has a separate
10-attempt budget per user and shares the source-address budget with login.

The counters are shared across API processes and survive restarts. Expired counters are pruned;
identifiers are hashed rather than kept as plaintext. A database failure returns 503 instead of
silently dropping the limit. This is a bounded temporary throttle, not a permanent account lockout.
Configuration and reverse-proxy considerations are in `OPERATIONS.md`.

## Two-factor authentication

Open **Security** (`/security`) while signed in. Enter the current password, scan the QR code in
an authenticator app (or enter the setup key manually), then enter its six-digit code to enable
2FA. The browser renders the QR locally; no secret is sent to a third-party QR service. Enrollment
expires after ten minutes and is bound to the session that started it. Starting over replaces the
pending secret; an unconfirmed setup never changes login requirements.

Implementation uses [PyOTP](https://pyauth.github.io/pyotp/) and
[RFC 6238](https://www.rfc-editor.org/rfc/rfc6238): SHA-1, six digits, 30-second steps, accepting
one step of clock skew in either direction. The last consumed step is stored under a user row
lock: neither replaying a code nor sending it concurrently creates another session. Enrollment
confirmation consumes its code too; wait for the next code before immediately signing in again.

TOTP secrets are encrypted with [Fernet](https://cryptography.io/en/latest/fernet/) and bound to the
user ID. The key comes from `SENTINEL_MFA_ENCRYPTION_KEY`, outside the database. If it is absent,
enrollment is unavailable. A missing/wrong key never downgrades an enabled account to password-only
login. Recovery codes still work because they are independently hashed, not encrypted.

Enabling displays **ten recovery codes once**. Each is a random 128-bit value whose SHA-256 hash
is stored; it replaces the authenticator code for one login or management action, always together
with the password. Consumption and session issuance share a transaction, so simultaneous reuse has
one winner. In Security, password plus an unused factor can regenerate the set or disable 2FA.
Regeneration invalidates all previous codes. Enabling, regenerating and disabling revoke all old
sessions, including the current token, and issue a fresh cookie to the requesting browser.

| Method | Endpoint | Request / response |
|---|---|---|
| GET | `/v1/auth/2fa` | `{enabled, setup_available, recovery_codes_remaining}`; no secrets |
| POST | `/v1/auth/2fa/setup` | `{password}` → `{secret, provisioning_uri, expires_at}` |
| POST | `/v1/auth/2fa/confirm` | `{password, code}` → `{recovery_codes}` + fresh cookie |
| POST | `/v1/auth/2fa/recovery-codes` | `{password, code}` → replacement `{recovery_codes}` + fresh cookie |
| POST | `/v1/auth/2fa/disable` | `{password, code}` → 204 + fresh cookie |

Every endpoint requires a full session; every mutation additionally rechecks the current password
and that the session is still live under the user lock. Setup/management errors are 401 for invalid
credentials or expired setup, 409 for incompatible enabled/disabled state, and 503 if the required
key is unavailable. No public signup, password reset, email/SMS fallback, forced enrollment, or
admin bypass/reset of an existing account's second factor is added. If both the authenticator and
all recovery codes are lost, an operator can revoke the account and provision a replacement through
the existing CLI. Keep the encryption key backed up separately from the database.

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

## The MITRE ATT&CK summary

`GET /v1/stats/mitre?days=30` (1-365, default 30): alert counts per technique in that window,
most frequent first. One alert with several techniques (a rule mapped to more than one, e.g.
`ssh-success-after-failures`'s `[T1110, T1078]`) counts once towards each — a coverage view of
"what techniques are firing", not a partition of alerts, so this is deliberate. Its own router and
URL prefix (`/v1/stats`, not `/v1/alerts/...`) on purpose: nothing about it should ever be able to
collide with the alert-detail catch-all path. The frontend's `/mitre` page renders it as a bar per
technique (width relative to the largest count that window), each linking to the technique's real
attack.mitre.org page; no local name lookup is kept, so it never drifts from the real taxonomy.

## The source-location map

`GET /v1/stats/geo?days=30` (1-365): alert counts grouped by city, for alerts with GeoIP
coordinates only (a non-public source, or a public one the database does not know, has nothing to
plot). Grouped by city and country code rather than exact coordinates, so repeated attacks from the
same metro area show as one sized dot instead of a scatter of near-duplicate points; the largest
`risk_score` seen in that city, within the window, decides its colour (the same low/medium/high/
critical scale as everywhere else in the dashboard). The frontend's `/map` page is a plain
equirectangular SVG scatter plot (a lat/lon graticule, no coastlines) — honestly a lightweight v1,
not a polished basemap; a real map library (e.g. Leaflet with tiles) is the natural next step if
this needs to look like an actual map rather than a chart of where things are.

## Incidents

`/incidents` lists shared triage cases, with a status filter and a creation form. An alert's detail
page links to that form with the alert preselected, or directly to its existing incident. `/incidents/:incidentId` shows the linked
alerts, the highest non-null risk score among them (or "Not scored"), an assignee and dated notes.
Both analysts and admins can create, claim, unassign, annotate and change the status of any case.
"Assign to me" uses the signed-in user; assigning another user is not exposed in this version.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/v1/incidents?status=&limit=` | Newest first; optional `new`, `investigating`, `closed` filter; limit 1–200, default 100 |
| POST | `/v1/incidents` | `{title, alert_ids?}`; creates a case and links alerts atomically; returns 201 |
| GET | `/v1/incidents/{id}` | Summary, linked alerts and notes (oldest first) |
| PATCH | `/v1/incidents/{id}` | `{status}`; close or reopen without losing notes or linked alerts |
| POST | `/v1/incidents/{id}/claim` | Assign to the current user |
| DELETE | `/v1/incidents/{id}/assignee` | Clear the assignee |
| POST | `/v1/incidents/{id}/notes` | `{body}`; author comes from the session |
| POST | `/v1/incidents/{id}/alerts` | `{alert_ids}`; link a batch of alerts |
| DELETE | `/v1/incidents/{id}/alerts/{alert_id}` | Unlink from this case; never deletes the alert or its evidence |

All routes require a user session. Mutations other than creation return 204. Titles are trimmed,
nonblank and at most 200 characters; notes are trimmed, nonblank and at most 4000 characters.
NUL characters are rejected because PostgreSQL cannot store them. Alert IDs must be full 64-character
lowercase hexadecimal IDs, with at most 200 per request. Unknown incidents return 404; invalid
input returns 422. Unknown alerts or alerts belonging to another incident return 409, with the
whole batch rolled back. Row locks serialize concurrent linking: an alert belongs to at most one
incident, and moving it requires explicitly unlinking it first. Linking again to the same incident
is harmless. Repeated closes retain the original `closed_at`; reopening clears it.

The detail page suggests the latest 200 alerts and also accepts an older alert's full ID from its
URL. Notes are plain text and immutable. There is no automatic grouping, incident deletion, title
editing, arbitrary-user assignment, pagination beyond the list limit, or full activity audit yet.
Apply migration `0007` before starting the updated API (the compose `migrate` service does this).

## The response API and the Blocks page

`api/response.py`, prefix `/v1/response`, and the `/blocks` page of the dashboard: what the
responder blocked (or would block, in dry run), and the allowlist. It is the dashboard face of
`sentinel blocks`, `sentinel unblock` and `sentinel allowlist`.

| Route | Who | What |
|---|---|---|
| `GET /blocks?limit=` | any signed-in account | Recent blocks with a computed `state` (`active`, `expired`, `released`), mode and who released it |
| `GET /allowlist` | any signed-in account | The database allowlist |
| `POST /blocks/unblock` `{address}` | **admin** | Releases every active block of the address and queues an `unblock` for the agents that applied it; 404 if nothing is active, 422 for a non-address (a network is refused) |
| `POST /allowlist` `{cidr, note}` / `DELETE /allowlist?cidr=` | **admin** | 409 if already listed, 404 if absent, 422 for garbage |

This is the first route gated on the `admin` role (`require_admin`, 403 for an analyst); the page
shows the same data read-only to analysts and hides every button. Each change is written to the
append-only audit log with the account as actor (`user:<email>`), like the CLI does with `cli`. In
the UI, lifting a block takes a second, explicit click ("Confirm unblock <address>"). CSRF is
covered as for every other route by the `SameSite=Strict` session cookie.

## The frontend

`frontend/` is a small single-page app: a login page, an alert list (auto-refreshing every 15 s,
filterable by rule id, each row linking to its detail page), an alert detail page (MITRE
techniques, when/who/where, the risk breakdown with every factor's reason, location and
reputation, the evidence table), a MITRE ATT&CK coverage page (`/mitre`), and a source-location
map (`/map`), incident list/detail pages (`/incidents`, `/incidents/:incidentId`), and the blocks page (`/blocks`) — behind a
session-aware router (`ProtectedRoute` redirects to
`/login` when `GET /v1/auth/me` says there is no session). Nothing here is dashboard-specific
framework code beyond what `api/client.ts` and `auth/AuthContext.tsx` need: no state management
library, no component kit — the surface is still small enough that plain React + `fetch` is the
simplest thing that works, and will be revisited if that stops being true.

**Look and feel.** One stylesheet (`src/index.css`) built on design tokens: colours, radii and shadows are
only ever used through CSS variables, in a light and a dark theme. The theme follows the system by
default; the button in the top bar forces one and remembers the choice (`localStorage`, guarded: the app
still works when storage is blocked, `src/theme.ts`). Severity and risk share one four-level scale
(low, medium, high, critical), also used for the map points; states (a block's mode, an incident's
status) are badges; a submit button is the primary action and `.danger` marks destructive ones; tables
scroll sideways inside a card on a small screen; the current page is marked in the navigation
(`aria-current`), focus is always visible and animations are switched off for people who ask for it.
Because the colours cannot be looked at from a test, `designTokens.test.ts` computes them: every
text/background pair the stylesheet uses must reach WCAG AA (4.5:1) in **both** themes, and the two copies
of the dark theme in the CSS must stay identical.

**Same origin, on purpose** (ADR 35): the API serves the built app directly (a catch-all route
falls back to `index.html` for client-routed paths like `/alerts`, so a hard refresh or a pasted
link still works), and `vite.config.ts` proxies `/v1` to the backend in dev for the same reason —
neither CORS nor a laxer `SameSite` is ever needed. `deploy/Dockerfile` builds `frontend/dist` in
its own stage and copies it into the final image; `SENTINEL_STATIC_DIR` (baked into the image) is
what tells the API to serve it. Run `npm run dev` (proxies to a backend on `:8000`) or
`npm run build && npm run preview` locally; `npm test`/`typecheck`/`lint`/`format:check` are the
same checks CI runs.

## Not done yet

- The map has no real basemap yet (see above).
- `role` RBAC covers account provisioning, incident triage and the response (admin only for changes);
  rules and agents will gain their routes, and their gates, later.
- Automated browser E2E in CI and a full authentication/activity audit remain future work.
