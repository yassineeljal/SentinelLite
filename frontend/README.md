# SentinelLite dashboard

React + Vite + TypeScript. Talks to the FastAPI backend over `/v1/*` on the **same origin**
(the session cookie is `SameSite=Strict`, see [`docs/DASHBOARD.md`](../docs/DASHBOARD.md)): in
production the API serves this app's built files directly (`deploy/Dockerfile`), and in dev
`vite.config.ts` proxies `/v1` to `http://127.0.0.1:8000` so it stays same-origin from the
browser's point of view too — no CORS setup anywhere.

## Develop

```bash
npm install
npm run dev          # http://localhost:5173, proxies /v1 to the backend (must be running)
```

## Checks (also run in CI)

```bash
npm run typecheck    # tsc -b
npm run lint         # oxlint
npm run format:check # prettier --check .   (npm run format to fix)
npm test             # vitest
npm run build        # tsc -b && vite build
```

## Layout

```
src/
├── api/        # typed fetch client + response types (kept in sync by hand with the backend)
├── auth/       # session state: AuthProvider, useAuth()
├── components/ # TopBar, ProtectedRoute
└── pages/      # Login, Alerts, AlertDetail, Mitre, Map, Incidents, IncidentDetail, Security
```

Incident triage supports creating a case from an alert, linking/unlinking alerts, assigning it to
yourself, notes, and closing/reopening. See `docs/DASHBOARD.md` for the API and limits.

`/security` provides optional TOTP setup, local QR rendering, recovery codes and authenticated
factor management. Login accepts an authenticator or recovery code for enrolled accounts.
The operator must configure the stable encryption key before enrollment is available
(`docs/OPERATIONS.md`). Secrets and recovery codes stay in component memory, never local storage.

Not built yet: a real map basemap and automated browser E2E in CI.
