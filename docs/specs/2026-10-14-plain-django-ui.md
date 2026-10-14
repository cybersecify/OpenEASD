# Plain-Django UI + single-image deployment (drop SPA + Ninja/JWT; keep DBOS + Postgres)

**Status:** Draft (spec) — 2026-10-14
**Supersedes:** the React SPA + Django-Ninja REST API + JWT auth as OpenEASD's UI/edge.
**Reference implementation:** `AmazonSP` (sibling repo on the same scan engine) already
made the UI move — `apps/mvp` (plain Django + vendored Bulma + vendored HTMX, Ninja/JWT/SPA
removed). This spec ports that pattern back into OpenEASD at a **basic** scope **and** packages
the app as a **single Docker image** that bundles PostgreSQL internally.

> **DB/engine decision (Option A):** DBOS durable workflows on PostgreSQL are **retained
> unchanged**. The "single image, no external DB" goal is met by **embedding Postgres inside
> the one container** (like GitLab-Omnibus / Supabase all-in-one), not by swapping to SQLite.
> A SQLite + Django-Q2 rewrite was considered and rejected: the runner writes
> `WorkflowStepResult`/`Finding` rows from *concurrent tool threads* (its phase-parallelism
> relies on Postgres handling concurrent writers), which SQLite's single-writer lock would
> turn into `database is locked` in the scan hot path — and it would mean ripping out and
> rewriting the hardened, tested DBOS execution + scheduling layer. Embedding Postgres keeps
> every engine guarantee (durable resume, concurrency, the H-series watchdogs) for ~a day of
> packaging work and zero app-code risk.

---

## 1. Goal

Replace OpenEASD's React 19 + Vite SPA and its Django-Ninja REST API + JWT auth with a
small, server-rendered Django UI (vendored **Bulma** CSS + vendored **HTMX**, no Node/npm),
backed by Django **session** auth. Views call the existing engine **service layer directly**
(`create_scan_session` → `run_scan_task`, `cancel`) — no serializers, no tokens. The scan
engine, DBOS pipeline, models, scheduler, verification, and issue/asset rollups are **untouched**.

Scope is deliberately **basic**: the daily-driver pages only. Advanced surfaces (Assets,
Changes, Workflows CRUD, Insights, Notifications, Credentials/BYOK, AI) are deferred and
remain fully functional via environment variables + Django admin. **No PDF generation.**

The deployment target is a **single Docker image with no external database container**:
PostgreSQL is **bundled inside** the image and started by the entrypoint alongside `gunicorn`
and `dbos_worker`. DBOS + Postgres (durable resume, concurrency, the H-series watchdogs) are
retained exactly as today; only the *packaging* collapses from 3 containers to 1. `pgdata`
lives on a mounted volume so scan history survives container replacement.

## 2. Motivation

- OpenEASD is **single-admin, no RBAC, no second backend consumer planned**
  (`project_single_user_app`, `project_keep_django_monolith`). The SPA+API split earns its
  keep when multiple/independent clients consume the backend; here there is exactly one UI,
  served from the same box. The architecture's main justification does not apply.
- **Proven, not speculative:** `AmazonSP` already runs the same scanner engine behind plain
  Django + HTMX, including the hard part — live scan-progress polling, stop-scan, findings
  tables, CSV export.
- **Simplification:** removes Node/npm/Vite, React, react-query, axios, the `frontend/`
  build, the CI `frontend` job, the Dockerfile node build stage, the SPA catch-all, and all
  JWT plumbing (localStorage tokens, the 401-refresh interceptor, token blacklist). Fewer
  deps → fewer CVEs → simpler ops. Session cookies (httponly) are also more secure than
  JWT-in-localStorage for a browser-only app.

This reverses the earlier "the template stack is retired; all UI is the React SPA" decision
in `CLAUDE.md` — a conscious, documented direction change. CLAUDE.md, the docs chain, and the
`feedback_backend_first_frontend_last` memory are updated as part of this work.

## 3. Scope

### 3.1 In scope — v1 pages (basic core)

A new Django app **`apps/mvp`** (label `mvp`) with `urls.py`, `views.py`, `templates/mvp/`,
`static/mvp/` (vendored `bulma.min.css`, `htmx.min.js`). All views are `@login_required`
except the auth pages.

| Route | View | What it does |
|---|---|---|
| `/login/` | Django `auth_views.LoginView` | Session login (`registration/login.html` or `mvp/` login template). |
| `/logout/` | Django `auth_views.LogoutView` | Logout → `/login/`. |
| `/change-password/` | `change_password` | Forced redirect when `must_change_password`; clears the flag on success. |
| `/` | `dashboard` | KPIs (domains, scans, findings-by-severity), domain list + status, recent scans, urgent findings. |
| `/activity/` | `dashboard_activity` | HTMX partial — recent-scan/activity refresh. |
| `/domains/add/` | `domain_create` (POST) | Add an apex domain (apex validation, with the subdomain hint). |
| `/domains/<name>/` | `domain_detail` | Domain detail: scans, findings, authorization + monitoring state. |
| `/domains/<name>/authorize/` | `domain_authorize` (POST) | Grant `DomainAuthorization` (attestation required). |
| `/domains/<name>/monitoring/` | `domain_monitoring` (POST) | Set/clear monitoring interval. |
| `/domains/<name>/delete/` | `domain_delete` (POST) | Delete domain + all scan data. |
| `/scan/start/` | `scan_start` (POST) | Start a scan: pick a **scan mode** (Passive Light/Deep, Active Light, Full) or an existing workflow; honors the passive no-auth bypass + the active-scan authorization gate. |
| `/scan/<uuid>/` | `scan_detail` | Scan detail: live HTMX progress, findings table (severity + verification filter), coverage banner, CSV link. |
| `/scan/<uuid>/progress/` | `scan_progress` | HTMX partial — per-tool step list, status KPIs, severity chips, failed/skipped coverage banner, stop button (polled `every 3s` while active). |
| `/scan/<uuid>/cancel/` | `scan_cancel` (POST) | Stop a running scan (status flip stops the pipeline). |
| `/scans/` | `scans` | Scan history list (filter by domain/status). |

Scan modes map to the predefined workflows by name (`buildScanModes` logic from the SPA,
reimplemented server-side): Passive Scan Light, Passive Scan Deep, Active Light, Full Scan;
`needsAuth` derives from `workflow.is_passive`. A mode whose workflow doesn't exist is omitted.

### 3.2 In scope — removals

- **React SPA:** delete `frontend/` (React, Vite, `package.json`, Vitest tests), the SPA
  catch-all + `spa()` view in `openeasd/urls.py`, and the `BuildInfo`/update-check SPA wiring.
- **Django-Ninja REST API + JWT:** delete `apps/core/console/api/` (the NinjaAPI instance,
  all per-module `api.py` routers, error handlers), remove `path("api/", api.urls)`, remove
  ninja-jwt/simplejwt token config from `settings/base.py`, and the login rate-limit
  middleware's `/api/token/pair` coupling (reassess: Django's auth + a simple throttle, or
  keep `LoginRateLimitMiddleware` retargeted at `/login/`).
- **PDF generation:** delete `export_scan_pdf` + the `/reports/<uuid>/pdf/` route + the
  WeasyPrint `_render_pdf` path + the PDF report template(s). **Keep CSV export.**
- **Dependencies** (`pyproject.toml`): drop `django-ninja`, `django-ninja-jwt`, `weasyprint`,
  and `pyjwt` **iff** nothing else references it (it was pinned only for the JWT CVE cluster).
  Re-lock with `uv lock`. Drop the WeasyPrint system libs (`libcairo2-dev`, `libpango*`,
  `libgdk-pixbuf*`) from CI + Dockerfile.
- **CI** (`.github/workflows/ci.yml`): remove the `frontend` job (node/npm/vitest/build);
  remove `frontend` from any `needs:`. The `publish` job already does **not** need it.
- **Docker** (`Dockerfile`): remove the `frontend-builder` node stage and the
  `COPY --from=frontend-builder .../dist/` line.

**Not removed:** DBOS, PostgreSQL, the scan engine, the scheduler/watchdogs — all retained
unchanged (see the DB/engine decision in the header and §4.6).

### 3.3 Out of scope — deferred to a later pass (v2)

These keep working via env vars + Django admin; they simply have no dedicated `mvp` UI yet:

- **Assets** inventory + **Changes** (delta) pages.
- **Workflows CRUD** UI — existing workflows stay *selectable* at scan start (read-only use);
  creating/editing workflows is done via Django admin in v1.
- **Insights** / Exposure-Score page.
- **Notifications** config UI — Slack/Teams stay env-configured (`NotificationConfig` via admin).
- **Credentials (BYOK)** UI — Shodan/HIBP/GitHub/DNS-history keys stay env-only in v1
  (the `get_credential()` resolver already falls back to env).
- **AI** triage/consent page — AI stays **off** in v1 (consent is UI-gated; no UI → no
  consent → the AI layer no-ops, which is already the default).

**Consequences to accept consciously:** (1) no in-app management of BYOK keys / AI consent /
alert channels in v1 (env + admin only); (2) CSV stays, PDF is removed entirely.

## 4. Architecture

### 4.1 View → service pattern (the AmazonSP model)

Plain function views, `@login_required`, that import and call the engine **service layer**
directly — never a serializer, never the (now-removed) API:

```python
from apps.core.engine.scans.pipeline import create_scan_session
from apps.core.engine.scans.tasks import run_scan_task

session = create_scan_session(domain, triggered_by="manual", workflow=wf, tools=tool_subset)
run_scan_task(session.id)          # durably enqueues the DBOS run_scan workflow
```

Reads go straight to the ORM (`Domain`, `ScanSession`, `Finding`, `Issue`, `Asset`,
`WorkflowRun`/`WorkflowStepResult`). The authorization gate (`DomainAuthorization`) and the
passive-tool no-auth bypass are enforced in the view the same way the API enforced them.

### 4.2 Live scan progress (HTMX)

`scan_detail.html` embeds a polled region:

```html
<div hx-get="{% url 'mvp:scan-progress' session.uuid %}"
     hx-trigger="load, every 3s" hx-swap="innerHTML"></div>
```

`scan_progress` renders `_scan_progress.html` (status KPIs, `steps_done/steps_total`,
finding count, severity chips, failed/skipped coverage banner, per-tool step table, and the
Stop button while `active`). Polling stops naturally when the scan reaches a terminal state
(the partial renders no live trigger once done — or the template drops the `every 3s`
trigger on terminal status). This replaces react-query's `refetchInterval: 3000`.

### 4.3 Auth

Django session auth. `auth_views.LoginView` + `LogoutView`; `LOGIN_URL = "/login/"`,
`LOGIN_REDIRECT_URL = "/"`. `must_change_password` (on `UserProfile`) forces a redirect to
`/change-password/` via a small middleware or a per-view check (reuse the existing flag;
the `docker-entrypoint.sh` first-run `admin/admin` creation is unchanged). Report CSV export
moves from "session or Bearer" to **session-only** (`login_required`), since there is no
Bearer anymore.

### 4.4 Templates & static

- `templates/mvp/base.html` — Bulma + the project dark palette (ported verbatim from
  AmazonSP's base), vendored `htmx.min.js`, nav, flash messages (`django.contrib.messages`).
- `static/mvp/bulma.min.css`, `static/mvp/htmx.min.js` — **vendored** (no CDN).
- Partials: `_scan_progress.html`, `_activity.html`, and small reusable chip snippets.
- Severity/status/verification chips as CSS classes (`.sev-*`, `.scan-*`, `.vd-*`).

### 4.5 URL layout (end state, mirrors AmazonSP)

```python
urlpatterns = [
    path("health/", health),            # plain JsonResponse (K8s probes) — unchanged shape
    path("favicon.ico", favicon),       # 204
    path("metrics/", metrics),          # opt-in Prometheus, unchanged
    path("admin/", admin.site.urls),
    path("reports/", include("apps.core.console.reports.urls")),  # CSV only (pdf removed)
    path("login/", auth_views.LoginView.as_view(), name="login"),
    path("logout/", auth_views.LogoutView.as_view(next_page="login"), name="logout"),
    path("", include("apps.mvp.urls")),
    re_path(r'^(?!admin|static/|media/|metrics/).*$', catch_all),  # → mvp:dashboard
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
```

`/health/`, `/metrics/` stay as plain Django views (already are — not Ninja). The
`/api/version/latest/` update-check and the SPA `BuildInfo` footer are dropped; build
provenance can surface as a muted footer in `base.html` reading `settings.OPENEASD_*`.

### 4.6 Single-image deployment — embedded Postgres, DBOS retained

The scan engine, DBOS durable workflows, the `@DBOS.scheduled` crons, and the Postgres schema
are **unchanged**. Only the *packaging* changes: 3 containers → 1.

- **One image, one container, three processes.** The entrypoint starts **PostgreSQL**
  (init the cluster on first run, then `pg_ctl start` against the mounted `pgdata`), waits
  for it to accept connections, runs `migrate` + `collectstatic` + first-run admin, then
  launches **`gunicorn openeasd.wsgi`** and **`python manage.py dbos_worker`**. A small
  process supervisor (`supervisord`/`honcho`, or a shell entrypoint with proper ordering and
  signal forwarding) keeps all three up and shuts them down cleanly. Postgres must be ready
  **before** the worker/web start (the role-aware entrypoint's existing DB-wait logic is
  reused, just pointed at `127.0.0.1`).
- **Postgres inside the image.** Install `postgresql` in the (Ubuntu-based) worker image —
  the single image already carries the scanner matrix + `NET_RAW`, so it is the natural base.
  `DB_HOST=127.0.0.1`, `DB_PORT=5432`, local socket. The DBOS `dbos` schema lives in the same
  local DB as today. `DATABASE_URL`/`DB_*` still override, so pointing at an **external**
  Postgres (the classic 3-tier deploy) remains possible — single-image is a packaging option,
  not a lock-in.
- **`pgdata` on a mounted volume.** `/var/lib/postgresql/data` (or `/data/pgdata`) must be a
  Docker volume / k8s PVC, or scan history is lost on container replacement. The entrypoint
  detects an empty volume and runs `initdb` + creates the role/db from `DB_*` on first boot.
- **Privilege-separation tradeoff (named).** Collapsing web+worker puts `NET_RAW` + offensive
  tooling on the same process group as the internet-facing web listener — the 3-tier model
  kept them apart. Acceptable for a single-admin internal tool; documented in OPERATIONS as
  the explicit cost of the single-image convenience. Teams that want the separation keep the
  existing multi-container compose/k8s path (both ship).
- **Concurrency unchanged:** real Postgres keeps `DBOS_SCAN_CONCURRENCY` and the runner's
  phase-parallel concurrent writers working — no serialization, no `database is locked`.
- **RAM:** Postgres adds ~150–300 MB on top of the engine's floor; keep the 2 GB-min / 4 GB-
  recommended guidance (Postgres memory is already sized by `k8s/postgres.yaml`'s rationale).

### 4.7 Compose / k8s shape

- **Docker:** a single-image **`docker run`** with a `pgdata` volume + a `logs` volume is the
  MVP's primary path. The existing 3-service `docker-compose.yml` is **kept** as the "external
  Postgres / privilege-separated" alternative.
- **k8s:** the single-image path is one Deployment with a PVC for `pgdata` (plus the probe
  Host header handling already documented). The existing 3-tier manifests stay as the
  scalable alternative. `test_k8s_manifests.py` is extended (not replaced) if a single-image
  manifest is added; whether k8s is in MVP scope at all is a plan-time call.

## 5. Settings changes (`openeasd/settings/base.py`)

- `INSTALLED_APPS`: add `"apps.mvp"`; remove `ninja`/`ninja_jwt`/`rest_framework_simplejwt`
  (and the api app if it is listed). **DBOS / Postgres / scheduler settings are unchanged.**
- Add `LOGIN_URL = "/login/"`, `LOGIN_REDIRECT_URL = "/"`.
- Remove the ninja-jwt / simplejwt token configuration block.
- `DATABASES` unchanged (Postgres, with the `DATABASE_URL`/`DB_*` config). The single-image
  deploy just sets `DB_HOST=127.0.0.1` against the bundled instance.
- `ROOT_URLCONF` unchanged (`openeasd.urls`), but the file is rewritten per §4.5.
- WhiteNoise/static still serve `static/mvp/*` (collectstatic picks up the app's static dir);
  `frontend/dist` is no longer collected.

## 6. Testing strategy

Replace the API endpoint tests (`tests/test_api_endpoints.py`, `test_api_*`) and the Vitest
suite with **Django test-client view tests** under `tests/unit/test_mvp_views.py`:

- `login_required` redirects anonymous users; login works; `must_change_password` forces
  the change-password redirect.
- `dashboard` / `scans` / `domain_detail` render (200) with seeded data.
- `scan_start`: passive mode starts **without** `DomainAuthorization` (no-auth bypass);
  active mode is **blocked** without it and allowed with it (mirror `test_passive_scan.py`
  expectations at the view layer).
- `scan_progress` partial renders step rows, severity chips, and the failed/skipped banner;
  `scan_cancel` flips status.
- `domain_authorize` / `domain_delete` / `domain_monitoring` POST behavior + CSRF.
- CSV export returns `text/csv` under session auth; the PDF route is **gone** (404/absent).
- Manifest/CI drift: a test asserting `frontend/` is not referenced by CI/Docker is optional.

Keep every existing **engine/tool/pipeline/DBOS/scheduler** test green — the engine and its
Postgres/DBOS layer are untouched, so `test_workflow_runner`, `test_durable_task`,
`test_scheduler`, the watchdog/reaper suites, and the CI `postgres:17-alpine` service all
stay. Only the UI edge changes. The coverage gate (`--cov-fail-under=80`) is re-evaluated
after the API code is removed (removing well-tested API code can move the percentage).

## 7. Cutover / sequencing

The UI port and the single-image packaging are independent; the engine is untouched, so there
is no engine-swap step.

1. Scaffold `apps/mvp` (app + base template + vendored Bulma/HTMX + auth wiring); `/login/`
   + `/` (dashboard) render against the live engine (Postgres + DBOS as-is).
2. Port the scan flow (start → detail → HTMX progress → cancel → CSV) — the core value.
3. Port domains (list/add/authorize/monitor/delete) + scans history.
4. Rewrite `openeasd/urls.py`; remove the SPA catch-all. Remove the Ninja API + JWT + PDF;
   drop deps (`django-ninja`, `django-ninja-jwt`, `weasyprint`, maybe `pyjwt`); `uv lock`;
   trim CI (frontend job) + Dockerfile (frontend-builder stage). Keep the CI Postgres service.
5. Swap tests (view tests in; API + Vitest out); re-check the coverage gate.
6. **Single-image packaging:** embed Postgres in the image + a supervised entrypoint
   (Postgres → migrate → gunicorn + dbos_worker) + `pgdata` volume. Keep the 3-service
   compose as the external-Postgres alternative.
7. Update docs (`CLAUDE.md` Stack/URL-layout/Status/Deployment, the `03-system`/`05-api`/
   `06-coding` layers, `CHANGELOG.md`) + the `feedback_backend_first_frontend_last` memory.

Each numbered step is independently testable and lands as its own commit on `dev`.

## 8. Risks & mitigations

- **Feature regression vs. the SPA:** v1 intentionally drops advanced pages. Mitigation:
  they stay functional via env/admin; §3.3 lists each and its fallback.
- **Reversing a settled decision:** documented explicitly here and in CLAUDE.md so it is a
  deliberate change, not drift.
- **Login rate-limit coupling:** `LoginRateLimitMiddleware` was keyed to `/api/token/pair`.
  Retarget it to `/login/` (or rely on Django auth + a simple throttle). Decide in the plan.
- **`must_change_password` enforcement** moves from an API check to a view/middleware check;
  cover it with a test so the first-run security flow can't silently regress.
- **CSV auth change:** report CSV becomes session-only (no Bearer). Acceptable — the only
  consumer was the SPA.
- **Single-image privilege loss:** web + worker (NET_RAW + offensive tooling) share one
  container. Named and accepted for the single-admin MVP; the 3-service compose/k8s path
  stays for anyone who wants the separation.
- **`pgdata` volume required:** an un-mounted single-image container loses scan history on
  replacement. The entrypoint must fail loudly (or clearly warn) if `pgdata` is ephemeral,
  and OPERATIONS must call out the volume as mandatory.
- **Two stateful processes in one container:** Postgres + app complicate restart/health
  semantics vs. a single process. Mitigation: a real supervisor with ordered startup, health
  gating (don't start web/worker until `pg_isready`), and signal forwarding for clean shutdown.

## 9. Not changing

The entire scan + execution + storage core is **retained unchanged**: the **30 tools / 13
phases**, the `run_workflow` runner and its `partial`/coverage semantics (incl. the cloud_enum
`run_capped` fix), **DBOS durable workflows + the `@scheduled` crons + the H-series
watchdogs**, **PostgreSQL** (+ the `dbos` schema), `DBOS_SCAN_CONCURRENCY` and the runner's
phase-parallel concurrent writers, the Finding/Issue/Asset models + rollups, verification, the
AI backend (dormant without consent), CSV export, `/health/` + `/metrics/`, the
`docker-entrypoint.sh` first-run admin flow, and the `OPENEASD_PROFILE` RAM tuning. **What
changes is only the edge:** SPA + Ninja/JWT → plain-Django + session (UI), PDF removed, and
3-tier → single-image *packaging* (Postgres embedded, not replaced).
