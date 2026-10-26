# OpenEASD — API

**There is no REST API.** The Django-Ninja REST API + JWT auth were removed on
2026-10-14. The UI is server-rendered plain Django (`apps/mvp`, Bulma + HTMX, session
auth) and calls the engine service layer directly.

The only HTTP surfaces that return data:

- `GET /reports/<uuid>/csv/` — CSV export of a scan (session auth; a user with
  `must_change_password` is redirected to `/change-password/`). Optional
  `?min_severity=<critical|high|medium|low|info>` filters rows (invalid value → 400).
  PDF export was removed.
- `GET /health/` — unauthenticated liveness/readiness JSON (build provenance).
- `GET /metrics/` — unauthenticated Prometheus exporter, **opt-in** (`METRICS_ENABLED`).

## UI routes (server-rendered, session auth)

Defined in `apps/mvp/urls.py` (namespace `mvp`) and `openeasd/urls.py`. HTML/HTMX
only; no JSON.

| Route | Purpose |
|---|---|
| `/` | Dashboard |
| `/login/`, `/logout/` | Session login / logout (Django auth views) |
| `/change-password/` | Forced change (MustChangePasswordMiddleware) |
| `/activity/` | Dashboard activity partial (HTMX) |
| `/domains/`, `/domains/add/` | List / add domain |
| `/domains/<name>/` (+ `authorize/`, `monitoring/`, `delete/`) | Domain detail and actions |
| `/scans/` | Scan history |
| `/scan/start/` | Start scan (2x2 modes + custom workflow) |
| `/scan/<uuid>/` (+ `progress/`, `cancel/`) | Scan detail, HTMX progress poll, stop |
| `/findings/` | Findings browser |
| `/issues/`, `/issues/<id>/update/` | Persistent Issue register, triage update |
| `/reports/<uuid>/csv/` | CSV export |
| `/health/`, `/metrics/` | Health probe, opt-in Prometheus exporter |
| `/admin/` | Django admin |

Unknown paths redirect to the dashboard (`catch_all`). If a programmatic API is ever
reintroduced it will be documented here as a new contract.
