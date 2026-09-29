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
└── pages/      # Login, Alerts
```

Not built yet: the map, the MITRE ATT&CK chart, incidents, 2FA (see `docs/DEVLOG.md` for what
each step actually shipped).
