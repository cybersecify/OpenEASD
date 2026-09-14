# OpenEASD — API Contract

OpenEASD is **API-driven and UI-agnostic**: the REST API under `/api/` is the one
published contract. The React SPA is just one client — anything that speaks HTTP + JWT
(curl, Python, Postman, a CLI, another service) drives the whole platform identically.

This document is the **stable half** of the contract — the conventions that rarely
change. It intentionally does **not** list endpoints, because that list would drift.

## The two sources of endpoint truth

- **Live OpenAPI spec** — `GET /api/openapi.json` (raw) and `GET /api/docs`
  (interactive Swagger UI). **Generated from the code, so it can never drift.** Point
  `openapi-generator` at it to produce a typed client SDK.
- **URL layout** in the root [`CLAUDE.md`](../CLAUDE.md) — a curated prose index of
  every route, grouped by perspective, for humans skimming.

If this doc and the OpenAPI spec ever disagree, **the spec wins** (it's generated).

## Conventions

### Authentication — JWT Bearer

| Step | Call |
|---|---|
| Log in | `POST /api/token/pair` → `{ "access", "refresh" }` |
| Authenticated request | header `Authorization: Bearer <access>` |
| Refresh an expired access token | `POST /api/token/refresh` (body `{ "refresh" }`) → new access |
| Log out | `POST /api/token/blacklist` (blacklists the refresh token) |
| Verify | `POST /api/token/verify` |

- Access tokens are short-lived; refresh tokens are long-lived. The SPA stores both in
  `localStorage`; a headless client keeps them in memory/secret store.
- **First login**: the seeded `admin` account carries `must_change_password=true` —
  most endpoints and report downloads are gated until `POST /api/user/change-password/`
  clears it.
- **Brute-force protection**: `POST /api/token/pair` is rate-limited per IP (429 +
  `Retry-After` after repeated failures). Other endpoints are not.

### Response shape — flat JSON, no envelope

Success is the object/collection itself; there is no `{ "data": … }` wrapper.

```jsonc
// success
{ "id": 1, "domain": "example.com", "status": "completed", ... }

// error — always this shape
{ "error": { "code": "NOT_FOUND", "message": "..." } }
```

Standard status codes apply: `200/201` success, `400` bad input (incl. unknown enum
values and unknown tool names), `401` missing/expired token, `404` not found, `409`
conflict (e.g. a scan already in flight), `429` rate-limited.

### Pagination

List endpoints are **page-based**: `?page=N` (and `?page_size=` where supported).
`page`/`page_size` are clamped to safe bounds (an out-of-range page never 500s). List
responses carry the navigation block:

```jsonc
{ "results…": [ ... ], "total": 128, "page": 2, "total_pages": 6,
  "has_next": true, "has_previous": true }
```

### Perspectives (the same facts, different lenses)

Because the backend is a domain-centric fact graph (see [`02-domain.md`](02-domain.md) /
[`03-system.md`](03-system.md)), the read API exposes several perspectives over one model —
add a new lens as a new read, with no schema change:

| Path | Lens |
|---|---|
| `/api/scans/` | scan-centric (lifecycle, per-run detail + status polling) |
| `/api/findings/` | raw per-scan findings + lifecycle status |
| `/api/assets/` | persistent, deduplicated asset inventory |
| `/api/issues/` | cross-scan issue register (triage persists here) |
| `/api/changes/` | scan-to-scan deltas |
| `/api/insights/` | trends, top hosts, exposure score |

### Versioning & health

- `GET /api/version/` — build provenance (version, git sha, build date); unauthenticated, `no-store`.
- `GET /api/version/latest/` — update-available check; authenticated, cached, fail-graceful.
- `GET /health/` — unauthenticated K8s probe (not under `/api/`).

### Reports (served by the web tier, not `/api/`)

`GET /reports/<uuid>/csv/` and `GET /reports/<uuid>/pdf/` accept **either** a session
cookie **or** an `Authorization: Bearer` header — so a headless client downloads them
with the same JWT. Both honour the `must_change_password` gate; `?min_severity=` filters.

## Adding an endpoint (contract change)

1. Add the handler to the relevant `apps/core/<module>/api.py` router.
2. Register the router in `apps/core/console/api/ninja.py` if the module is new.
3. The OpenAPI spec updates automatically — **no manual contract edit needed**; update
   this doc only if a *convention* (auth, error shape, pagination) changes.

See the full end-to-end headless walkthrough (auth → scan → poll → read → report) in
the project docs, and the route index in [`CLAUDE.md`](../CLAUDE.md).
