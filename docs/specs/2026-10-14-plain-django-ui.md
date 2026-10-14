# Plain-Django UI + single-image deployment (drop SPA, Ninja/JWT, DBOS & Postgres)

**Status:** Draft (spec) — 2026-10-14
**Supersedes:** (1) the React SPA + Django-Ninja REST API + JWT auth as OpenEASD's UI/edge;
(2) **DBOS durable workflows on PostgreSQL** as the execution/scheduling engine.
**Reference implementation:** `AmazonSP` (sibling repo on the same scan engine) already
made the UI move — `apps/mvp` (plain Django + vendored Bulma + vendored HTMX, Ninja/JWT/SPA
removed). This spec ports that pattern back into OpenEASD at a **basic** scope **and** adds a
single-container, no-Postgres deployment: **SQLite + Django-Q2** replace Postgres + DBOS.

> **Note:** AmazonSP kept Postgres + DBOS. The DB/engine change below is OpenEASD-specific —
> chosen so the MVP ships as **one Docker image with no external database**.

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

The deployment target is a **single Docker image with no external database**: the app data +
task queue live in **SQLite** (WAL), and **Django-Q2** (ORM broker) replaces DBOS for task
execution + scheduling. One container runs `gunicorn` + one `qcluster` worker. This trades
away DBOS's durable mid-scan resume and real write-concurrency (SQLite is single-writer, so
scans serialize) — both acceptable for a single-admin, single-box tool, and the stuck-scan
watchdog still reaps a crashed scan.

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
- **DBOS + Postgres:** remove the `apps/core/engine/durable/` DBOS module (the `run_scan`
  workflow, `@DBOS.step` phase wrappers, `@durable_task`, the `@DBOS.scheduled` crons, the
  DBOS queue/client), the `dbos` dependency, all `DBOS_*` settings + the `dbos` LOGGING
  entry, and the Postgres `DATABASES` branch. Replace with SQLite + Django-Q2 (§4.6). The
  3-tier docker-compose / k8s manifests collapse to the single-image model (§4.7).

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

### 4.6 Execution & scheduling — DBOS/Postgres → Django-Q2/SQLite

**Why Django-Q2 (not Huey/Celery):** the repo already ran on Django-Q2 before the DBOS
migration (`test_qcluster_config.py` and the `reap_stuck_scans`/scheduler callables survive),
its **ORM broker** uses the Django DB itself as the queue (no Redis, no Postgres — works on
SQLite), and its **DB-backed `Schedule` model is visible/editable in Django admin**, which
maps the system crons cleanly.

**The execution path already exists un-DBOS'd.** `run_scan(session_id)` →
`_run_via_workflow` → `run_workflow(run_id)` already runs every phase **in-process,
synchronously** (the runner catches a failing tool → `partial`); the DBOS layer is only a
checkpointing *wrapper* (`apps/core/engine/durable/workflows.py` calls the same
`run_one_phase_group`/`finalize` internals via `@DBOS.step`s). So the swap is mostly
**re-pointing the enqueue adapter**, not rewriting the engine:

- **Task adapter (H6 seam):** `apps/core/engine/scans/tasks.py::run_scan_task(session_id)`
  changes from "enqueue the DBOS `run_scan` workflow" to `async_task("apps.core.engine.
  scans.pipeline.run_scan", session_id)` (Django-Q2). `run_scan` runs the full pipeline
  synchronously in the `qcluster` worker — one task per scan, **no per-phase checkpoint/
  resume**. The `@durable_task` decorator (ai_triage, agent_step) is reimplemented as a thin
  `async_task` wrapper so callers are unchanged (AI stays dormant in v1 anyway).
- **Schedules:** the four/five `@DBOS.scheduled` crons (daily scan, monitoring sweep,
  user-schedule sweep, **stuck-scan watchdog**, token purge, scan-prune) become Django-Q2
  `Schedule` rows seeded by a data migration (type `CRON`), dispatching the **existing**
  scheduler callables (`daily_scan`, `run_due_monitoring_scans`, `run_due_user_scans`,
  `reap_stuck_scans`, `purge_expired_blacklisted_tokens`, `prune_old_scans`). The
  `SCHEDULED_SCANS_ENABLED` master switch is preserved by gating at the callable (as today).
- **`Q_CLUSTER` config** (settings): `{"name": "openeasd", "orm": "default",
  "workers": <1–2>, "timeout": <SCAN_TASK_TIMEOUT-ish>, "retry": <timeout+buffer>,
  "catch_up": False, "poll": 2, "save_limit": …, "sync": False}`. `orm: "default"` = SQLite
  broker. `catch_up False` so a downtime doesn't stampede missed crons.
- **Concurrency:** one scan at a time in practice (SQLite single-writer + modest workers).
  `DBOS_SCAN_CONCURRENCY` is retired; a per-domain active-scan guard still prevents double
  runs. **No durable resume** — a worker crash fails the in-flight task; `reap_stuck_scans`
  (now a Django-Q schedule) flips it to `failed`/`partial` and frees it.
- **Idempotency note:** the runner's resume-dedup logic (delete-stale-findings-before-rerun,
  F1b/H5) becomes mostly moot without checkpointed resume, but is harmless to keep — a
  Django-Q `retry` of a failed whole-scan task re-enters `run_workflow`, which still
  delete-then-inserts per tool, so a retry converges rather than duplicating.

### 4.7 Single-image, no-Postgres deployment

- **One image, one container.** The role split (web/worker) collapses: the entrypoint runs
  `migrate` then launches **both** `gunicorn openeasd.wsgi` and `python manage.py qcluster`
  in the same container (via `honcho`/a small supervisor, or `qcluster` backgrounded). The
  worker still needs `NET_RAW` for nmap/naabu, so the single image carries the scanner matrix
  (the privilege-separation of the 3-tier model is traded for simplicity — a conscious MVP
  choice, documented).
- **SQLite file on a volume.** `DATABASES["default"]` = `django.db.backends.sqlite3`, `NAME`
  pointing at a path under a mounted volume (e.g. `/data/openeasd.sqlite3`) so scan history
  survives container replacement. **WAL mode + busy timeout** set via a `connection_created`
  signal (`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=20000; PRAGMA synchronous=NORMAL;`).
- **docker-compose / k8s:** the Postgres service + the separate worker Deployment/StatefulSet
  are removed; a single Deployment (or `docker run`) with a PVC for `/data`. `test_k8s_
  manifests.py` is rewritten for the single-workload shape (or dropped if k8s is out of MVP
  scope — decide in the plan).
- **RAM profile unchanged:** `OPENEASD_PROFILE` still tunes nuclei/amass; a 1–2 GB box with
  swap is still the floor.

## 5. Settings changes (`openeasd/settings/base.py`)

- `INSTALLED_APPS`: add `"apps.mvp"` and `"django_q"`; remove `ninja`/`ninja_jwt`/
  `rest_framework_simplejwt` and `"apps.core.engine.durable"`.
- Add `LOGIN_URL = "/login/"`, `LOGIN_REDIRECT_URL = "/"`.
- Remove the ninja-jwt / simplejwt token configuration block and every `DBOS_*` setting + the
  `dbos` LOGGING handler.
- `DATABASES`: replace the Postgres branch with SQLite (`ENGINE: sqlite3`, `NAME` on the
  `/data` volume). Keep the `DATABASE_URL` escape hatch for anyone who *does* want Postgres.
- Add the `Q_CLUSTER` dict (§4.6) with `orm: "default"`.
- Add a `connection_created` signal that issues the WAL/busy_timeout PRAGMAs for SQLite.
- `ROOT_URLCONF` unchanged (`openeasd.urls`), but the file is rewritten per §4.5.
- WhiteNoise/static still serve `static/mvp/*` (collectstatic picks up the app's static dir);
  `frontend/dist` is no longer collected.
- **Dependencies:** add `django-q2`; remove `dbos` (and the Postgres-only extras if any).

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

**Engine/DB swap tests:**
- Scans run end-to-end on **SQLite** via Django-Q2 in **sync mode** (`Q_CLUSTER["sync"]=True`
  under pytest, as the old Django-Q tests did) — a scan reaches a terminal status and writes
  findings with no Postgres/DBOS present.
- A failing tool still yields `partial` (the runner path is unchanged — the cloud_enum fix
  and `test_workflow_runner` partial tests stay green).
- The seeded Django-Q `Schedule` rows exist for the system crons and dispatch the right
  callables; `SCHEDULED_SCANS_ENABLED=False` makes the scan crons no-op.
- `reap_stuck_scans` still flips a stale running/pending scan to terminal (ported from
  `test_scheduler.py`).
- The CI `postgres:17-alpine` **service container is removed**; tests run against SQLite.

Keep every existing **engine/tool/pipeline** test green (they do not touch the UI). The DBOS-
specific tests (`test_durable_task.py`, `test_watchdog_reconcile.py`'s DBOS-cancel assertions,
`test_orphan_reaper.py`, `test_qcluster_config.py`'s DBOS invariants) are removed or rewritten
for Django-Q2. The coverage gate (`--cov-fail-under=80`) is re-evaluated after the API + DBOS
code is removed.

## 7. Cutover / sequencing

The two subsystems (UI and DB/engine) are **largely independent** — do the engine swap first
so the UI is built against the final stack:

1. **DB/engine swap:** SQLite (WAL) + Django-Q2 (ORM broker). Re-point `run_scan_task` to
   `async_task`; reimplement `@durable_task` as an `async_task` wrapper; seed the system-cron
   `Schedule` rows (data migration); remove `apps/core/engine/durable/` + DBOS deps/settings.
   Get a scan running green on SQLite (sync mode under tests).
2. Scaffold `apps/mvp` (app + base template + vendored Bulma/HTMX + auth wiring); `/login/`
   + `/` (dashboard) render against the live engine.
3. Port the scan flow (start → detail → HTMX progress → cancel → CSV) — the core value.
4. Port domains (list/add/authorize/monitor/delete) + scans history.
5. Rewrite `openeasd/urls.py`; remove the SPA catch-all. Remove the Ninja API + JWT + PDF;
   drop deps; `uv lock`; trim CI (frontend job + postgres service) + Dockerfile.
6. Single-image entrypoint (gunicorn + qcluster) + SQLite volume; collapse compose/k8s.
7. Swap tests (view + SQLite/Q2 tests in; API/Vitest/DBOS out); re-check the coverage gate.
8. Update docs (`CLAUDE.md` Stack/URL-layout/Status/Deployment, the `03-system`/`05-api`/
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
- **SQLite `database is locked`:** `qcluster` polling + web writes contend on SQLite's single
  writer. Mitigation: WAL + `busy_timeout=20000` + `synchronous=NORMAL`, 1–2 workers, `poll:2`.
  For single-user throughput this is sufficient; if it bites, the `DATABASE_URL` escape hatch
  restores Postgres without code changes.
- **No durable mid-scan resume:** a crash loses the in-flight scan (vs. DBOS checkpoint/
  resume). `reap_stuck_scans` flips it terminal and frees the domain; the user re-runs. Named
  as an accepted MVP tradeoff, not a regression to fix.
- **Scans serialize:** SQLite has no write concurrency, so concurrent scans effectively
  queue. Fine for a single admin; documented so it isn't mistaken for a bug.

## 9. Not changing

The scan engine itself — the **30 tools / 13 phases**, the `run_workflow` runner and its
`partial`/coverage semantics (incl. the cloud_enum `run_capped` fix), the Finding/Issue/Asset
models + rollups, verification, the AI backend (dormant without consent), CSV export,
`/health/` + `/metrics/`, the `docker-entrypoint.sh` first-run admin flow, and the
`OPENEASD_PROFILE` RAM tuning. **What changes is the layer around the engine:** DBOS→Django-Q2
(execution + scheduling), Postgres→SQLite (storage + broker), 3-tier→single-image
(deployment), and SPA+Ninja/JWT→plain-Django+session (UI/edge).
