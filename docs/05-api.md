# OpenEASD — API

**There is no REST API.** The Django-Ninja REST API + JWT auth were removed on
2026-10-14. The UI is server-rendered plain Django (`apps/mvp`, Bulma + HTMX, session
auth) and calls the engine service layer directly.

The only HTTP surfaces that return data:

- `GET /reports/<uuid>/csv/` — CSV export of a scan (session auth; honours
  `must_change_password`). PDF export was removed.
- `GET /health/` — unauthenticated liveness/readiness JSON (build provenance).
- `GET /metrics/` — unauthenticated Prometheus exporter, **opt-in** (`METRICS_ENABLED`).

UI routes are listed in the root [`CLAUDE.md`](../CLAUDE.md) (URL layout) and
`apps/mvp/urls.py`. If a programmatic API is ever reintroduced it will be documented
here as a new contract.
