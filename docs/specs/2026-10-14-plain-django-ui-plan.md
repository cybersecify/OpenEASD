# Plain-Django UI + single-image deployment — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace OpenEASD's React SPA + Django-Ninja/JWT API with a basic plain-Django,
server-rendered UI (vendored Bulma + HTMX, Django session auth), keep DBOS + Postgres, remove
PDF, and package the app as a single Docker image with Postgres embedded.

**Architecture:** A new `apps/mvp` Django app holds all UI (urls/views/templates/static). Views
are `@login_required` and call the engine **service layer directly** (`create_scan_session` →
`run_scan_task`, `cancel`) — no serializers, no tokens. HTMX polls live scan progress. The
scan engine, DBOS durable workflows, scheduler, and Postgres schema are **untouched**.

**Tech Stack:** Django 5.2, DBOS (unchanged), PostgreSQL (unchanged, embedded in the single
image), vendored Bulma CSS + HTMX JS, Django `contrib.auth` session login, WhiteNoise static.

**Spec:** `docs/specs/2026-10-14-plain-django-ui.md`

**Reference implementation:** the sibling repo `/Users/rathnakara/project/AmazonSP`, app
`apps/mvp`, already implements this exact pattern on the same engine. Where a task says "port
from AmazonSP", copy that file and adapt the named differences — do not invent a new shape.

## Global Constraints

- **Branch:** all work commits directly to the `dev` branch (no `feat/`/`fix/` sub-branches,
  no PRs) per the current session instruction. Commit messages omit the `Co-Authored-By:
  Claude` trailer (memory `feedback_no_claude_coauthor`).
- **Commands:** always `uv run python`, `uv run manage.py`, `uv run pytest` (never bare
  `python`/`pytest`). Fast suite: `uv run pytest tests/ --ignore=tests/unit/test_domain_security.py`.
- **Auth:** session only. Every UI view except the auth pages is `@login_required`. No JWT,
  no Bearer. The `must_change_password` flow is preserved (forced redirect).
- **Authorization boundary (unchanged semantics):** a passive-only scan started "now" bypasses
  `DomainAuthorization`; any active tool requires it. The view layer must enforce exactly what
  `apps/core/engine/scans/api.py` enforced — reuse `registry.is_passive_tool_set` +
  `DomainAuthorization`.
- **No Node/npm/CDN:** Bulma + HTMX are vendored under `apps/mvp/static/mvp/`.
- **Engine is off-limits:** do not modify `apps/core/engine/` execution/DBOS/scheduler code,
  the scan models, or the tool apps. Only the UI edge, reports auth, urls, settings, CI,
  Docker, and docs change.
- **Reports:** CSV kept, PDF removed.
- **Keep green:** every existing engine/tool/pipeline/DBOS/scheduler test must still pass; the
  coverage gate is `--cov-fail-under=80`.

---

## File Structure

**Created:**
```
apps/mvp/__init__.py
apps/mvp/apps.py                      — AppConfig (label "mvp")
apps/mvp/urls.py                      — app_name="mvp", the UI routes
apps/mvp/views.py                     — all plain-Django views
apps/mvp/middleware.py                — MustChangePasswordMiddleware (forced redirect)
apps/mvp/templates/mvp/base.html      — Bulma + HTMX shell, dark palette, nav, flash msgs
apps/mvp/templates/mvp/dashboard.html
apps/mvp/templates/mvp/domains.html
apps/mvp/templates/mvp/domain_detail.html
apps/mvp/templates/mvp/scan_start.html
apps/mvp/templates/mvp/scan_detail.html
apps/mvp/templates/mvp/scans.html
apps/mvp/templates/mvp/change_password.html
apps/mvp/templates/mvp/_scan_progress.html   — HTMX partial (polled)
apps/mvp/templates/registration/login.html   — Django LoginView template
apps/mvp/static/mvp/bulma.min.css     — vendored (copied from AmazonSP)
apps/mvp/static/mvp/htmx.min.js       — vendored (copied from AmazonSP)
tests/unit/test_mvp_views.py          — view tests (replace API/Vitest coverage)
docker/entrypoint-singleimage.sh      — embedded-Postgres supervised entrypoint
docker/Procfile                       — honcho process list (postgres already up): web + worker
```

**Modified:**
```
openeasd/settings/base.py             — INSTALLED_APPS (+apps.mvp, -ninja/-jwt), LOGIN_URL, drop JWT cfg
openeasd/urls.py                      — rewrite: mvp + login/logout, drop /api/ + SPA catch-all
apps/core/console/reports/views.py    — CSV session-only auth; remove export_scan_pdf + PDF helpers
apps/core/console/reports/urls.py     — drop the /pdf/ route
apps/core/console/api/ratelimit.py    — LoginRateLimitMiddleware retargeted to POST /login/
pyproject.toml                        — drop django-ninja, django-ninja-jwt, weasyprint, (pyjwt?)
.github/workflows/ci.yml              — remove the `frontend` job; drop WeasyPrint system libs
Dockerfile                            — drop frontend-builder node stage + COPY; add single-image target
docker-compose.yml                    — keep 3-service as the alt; add single-image compose (or a note)
CLAUDE.md, docs/03-system.md, docs/05-api.md, docs/06-coding.md, docs/04-technical.md,
docs/OPERATIONS.md, CHANGELOG.md      — doc layer updates
```

**Deleted:**
```
frontend/                             — the entire React SPA (incl. its Vitest tests)
apps/core/console/api/                — the NinjaAPI instance + all routers + JWT auth
tests/test_api_endpoints.py, tests/unit/test_api_*.py, tests/unit/test_login_ratelimit.py(*)
  (* only if the middleware is retired rather than retargeted — see Task 11)
PDF report template(s) under apps/core/console/reports/templates/
```

---

## Task 1: Scaffold `apps/mvp` + session auth shell

**Files:**
- Create: `apps/mvp/__init__.py`, `apps/mvp/apps.py`, `apps/mvp/urls.py`, `apps/mvp/views.py`,
  `apps/mvp/templates/mvp/base.html`, `apps/mvp/templates/registration/login.html`,
  `apps/mvp/static/mvp/bulma.min.css`, `apps/mvp/static/mvp/htmx.min.js`
- Modify: `openeasd/settings/base.py` (INSTALLED_APPS `+"apps.mvp"`, `LOGIN_URL="/login/"`,
  `LOGIN_REDIRECT_URL="/"`), `openeasd/urls.py` (add login/logout + `include("apps.mvp.urls")`
  temporarily alongside the existing SPA — full rewrite is Task 8)
- Test: `tests/unit/test_mvp_views.py`

**Interfaces:**
- Produces: `apps.mvp.urls` with `app_name="mvp"` and a `dashboard` route named
  `mvp:dashboard`; a `base.html` other templates `{% extends "mvp/base.html" %}`.

- [ ] **Step 1: Copy vendored assets + base template from AmazonSP.** Copy
  `AmazonSP/apps/mvp/static/mvp/{bulma.min.css,htmx.min.js}` and
  `AmazonSP/apps/mvp/templates/mvp/base.html` verbatim (base.html already carries the dark
  palette + HTMX script tag). Change the `<title>` block default to "OpenEASD".

- [ ] **Step 2: Write `apps.py` + `urls.py` + a stub `dashboard` view** returning
  `render(request, "mvp/base.html")` under `@login_required`, route `path("", views.dashboard,
  name="dashboard")`, `app_name="mvp"`.

- [ ] **Step 3: Wire settings + root urls (additive).** Add `"apps.mvp"` to INSTALLED_APPS,
  `LOGIN_URL`/`LOGIN_REDIRECT_URL`; add to `openeasd/urls.py`:
  `path("login/", auth_views.LoginView.as_view(), name="login")`,
  `path("logout/", auth_views.LogoutView.as_view(next_page="login"), name="logout")`,
  `path("app/", include("apps.mvp.urls"))` (temporary prefix so it coexists with the SPA until
  Task 8).

- [ ] **Step 4: Write the failing test.**
```python
# tests/unit/test_mvp_views.py
import pytest
from django.contrib.auth.models import User

@pytest.mark.django_db
class TestAuthShell:
    def test_dashboard_requires_login(self, client):
        resp = client.get("/app/")
        assert resp.status_code == 302 and "/login/" in resp["Location"]

    def test_dashboard_renders_when_logged_in(self, client):
        User.objects.create_user("admin", password="pw12345!")
        client.login(username="admin", password="pw12345!")
        assert client.get("/app/").status_code == 200
```

- [ ] **Step 5: Run it, confirm pass:** `uv run pytest tests/unit/test_mvp_views.py -v`

- [ ] **Step 6: Commit** on `dev`: `feat: scaffold apps/mvp plain-Django UI shell + session auth`

---

## Task 2: Dashboard page

**Files:**
- Modify: `apps/mvp/views.py` (`dashboard`), Create: `apps/mvp/templates/mvp/dashboard.html`
- Test: `tests/unit/test_mvp_views.py`

**Interfaces:**
- Consumes: `Domain`, `ScanSession`, `Finding` models; `_severity_counts` helper (port from
  AmazonSP `apps/mvp/views.py`).
- Produces: `mvp:dashboard` rendering KPIs + domain list + recent scans + urgent findings.

- [ ] **Step 1: Port `dashboard` + `_severity_counts` + `dashboard_activity` from AmazonSP**
  `apps/mvp/views.py`. Adapt model imports to OpenEASD paths (identical: `apps.core.data.
  domains.models.Domain`, `apps.core.engine.scans.models.ScanSession`,
  `apps.core.data.findings.models.Finding`). Add an `/activity/` route + `_activity.html`
  partial for the HTMX recent-scans refresh.

- [ ] **Step 2: Port `dashboard.html`** from AmazonSP; adapt copy ("SP-API DPP" → "OpenEASD",
  remove the pentest-specific "test/retest" framing). KPI tiles: active domains, scans,
  findings-by-severity; a domain table with per-domain latest-scan status; an urgent-findings
  (critical/high) list.

- [ ] **Step 3: Write failing tests** — seed a `Domain` + a completed `ScanSession` + a couple
  `Finding`s; assert `client.get("/app/")` is 200 and the response contains the domain name and
  a severity count. Run, make pass.

- [ ] **Step 4: Commit** on `dev`: `feat: mvp dashboard (KPIs, domains, recent scans, urgent findings)`

---

## Task 3: Domains — list, detail, add, authorize, monitoring, delete

**Files:**
- Modify: `apps/mvp/views.py` (`domains`, `domain_detail`, `domain_create`, `domain_authorize`,
  `domain_monitoring`, `domain_delete`), `apps/mvp/urls.py`
- Create: `apps/mvp/templates/mvp/domains.html`, `apps/mvp/templates/mvp/domain_detail.html`
- Test: `tests/unit/test_mvp_views.py`

**Interfaces:**
- Consumes: `Domain`, `DomainAuthorization` (`is_authorized`, attestation fields), the apex
  helpers `apps.core.engine.scans.domain_utils.{is_apex,registrable_apex}`.
- Produces: routes `mvp:domains`, `mvp:domain-detail` (`<str:name>`), and the POST routes
  `mvp:domain-create`, `mvp:domain-authorize`, `mvp:domain-monitoring`, `mvp:domain-delete`.

- [ ] **Step 1: Port the domain views** from AmazonSP (`domain_create`, `domain_detail`,
  `domain_authorize`, `domain_delete`) + add `domain_monitoring` (POST sets/clears
  `Domain.monitoring_interval_hours` — mirror the SPA's `/api/domains/<pk>/monitoring/`
  behavior). All POST views `@require_POST` + CSRF. Reuse `_clean_domain`, `_is_apex`,
  `_apex_hint`, `_VALID_HOSTNAME`.

- [ ] **Step 2: Port the templates**; `domain_detail.html` shows authorization state +
  monitoring + the domain's scans + findings, and hosts the Scan-start form (Task 4).

- [ ] **Step 3: Write failing tests** (logged in): add a domain (POST → 302 + row exists);
  reject a non-apex with the apex hint; authorize (POST → `DomainAuthorization.is_authorized`
  True); delete (POST → gone). Run, make pass.

- [ ] **Step 4: Commit** on `dev`: `feat: mvp domains (list/detail/add/authorize/monitor/delete)`

---

## Task 4: Scan start — 2×2 modes + workflow pick + auth gate

**Files:**
- Modify: `apps/mvp/views.py` (`scan_start`, `_scan_modes`), `apps/mvp/urls.py`
- Create: `apps/mvp/templates/mvp/scan_start.html` (or fold the form into `domain_detail.html`)
- Test: `tests/unit/test_mvp_views.py`

**Interfaces:**
- Consumes: `create_scan_session(domain, triggered_by, workflow=None, tools=None)` and
  `run_scan_task(session_id)` (`apps.core.engine.scans.pipeline` / `.tasks`); `Workflow`
  (predefined-by-name); `registry.is_passive_tool_set`; `DomainAuthorization.is_authorized`.
- Produces: route `mvp:scan-start` (POST) → redirect to `mvp:scan-detail`.

- [ ] **Step 1: Write `_scan_modes()`** — server-side port of the SPA's `buildScanModes`.
  Resolve the four predefined workflows by name and expose `needsAuth` from
  `workflow.is_passive`; omit a cell whose workflow is absent:
```python
SCAN_MODE_DEFS = [
    ("Passive Scan Light", "passive-light", "Apex-only passive first look"),
    ("Passive Scan Deep",  "passive-deep",  "Full passive recon (no auth)"),
    ("Active Light",       "active-light",  "Fast authorized scan"),
    ("Full Scan",          "full",          "Complete active scan"),
]
def _scan_modes():
    from apps.core.engine.workflows.models import Workflow
    modes = []
    for name, slug, blurb in SCAN_MODE_DEFS:
        wf = Workflow.objects.filter(name=name).first()
        if wf:
            modes.append({"slug": slug, "name": name, "blurb": blurb,
                          "workflow_id": wf.id, "needs_auth": not wf.is_passive})
    return modes
```

- [ ] **Step 2: Write `scan_start`** (`@login_required @require_POST`): resolve the chosen
  workflow by `workflow_id`; apex-guard the domain; **enforce the auth boundary** — if the
  resolved workflow is **not** passive (`not wf.is_passive`) and the domain is not authorized,
  `messages.error` + redirect (mirror `scans/api.py`); then `create_scan_session(domain,
  triggered_by="manual", workflow=wf)` → `run_scan_task(session.id)` → redirect to
  `mvp:scan-detail`. A passive workflow with no authorization proceeds (bypass).

- [ ] **Step 3: Template** — render `_scan_modes()` as a 2×2 grid of start buttons on
  `domain_detail` (+ a "custom: pick workflow" dropdown of all workflows).

- [ ] **Step 4: Write failing tests** — (a) a **passive** mode starts without any
  `DomainAuthorization` (session created, `run_scan_task` patched/asserted called); (b) an
  **active** mode is **blocked** without authorization and **allowed** with it. Mirror the
  expectations in `tests/unit/test_passive_scan.py`. Patch `run_scan_task` to avoid executing a
  real scan. Run, make pass.

- [ ] **Step 5: Commit** on `dev`: `feat: mvp scan start (2x2 modes, workflow pick, auth gate)`

---

## Task 5: Scan detail + HTMX live progress + cancel

**Files:**
- Modify: `apps/mvp/views.py` (`scan_detail`, `scan_progress`, `scan_cancel`,
  `_scan_progress_ctx`, `_scan_steps`), `apps/mvp/urls.py`
- Create: `apps/mvp/templates/mvp/scan_detail.html`, `apps/mvp/templates/mvp/_scan_progress.html`
- Test: `tests/unit/test_mvp_views.py`

**Interfaces:**
- Consumes: `WorkflowRun`/`WorkflowStepResult` (`run.step_results`), `Finding`,
  `ScanSession.status`; the scan-cancel path (`ScanSession` status flip — reuse the service the
  SPA's `/api/scans/<uuid>/stop/` used; find it in `apps/core/engine/scans/`).
- Produces: routes `mvp:scan-detail` (`<uuid>`), `mvp:scan-progress` (`<uuid>`, HTMX partial),
  `mvp:scan-cancel` (`<uuid>`, POST).

- [ ] **Step 1: Port `_scan_steps`, `_scan_progress_ctx`, `scan_detail`, `scan_progress`,
  `scan_cancel`** from AmazonSP verbatim (they already use OpenEASD model paths). `scan_detail`
  renders the findings table filterable by `?sev=` with a verification-verdict column; the CSV
  link points at `/reports/<uuid>/csv/`.

- [ ] **Step 2: Port `_scan_progress.html`** verbatim (status KPIs, `steps_done/steps_total`,
  severity chips, failed/skipped coverage banner, per-tool step table, Stop button while
  active). In `scan_detail.html` embed the poll region:
```html
<div hx-get="{% url 'mvp:scan-progress' session.uuid %}"
     hx-trigger="load, every 3s" hx-swap="innerHTML"></div>
```
  Drop the `every 3s` trigger once `session.status` is terminal (render the partial without the
  live trigger when not `active`) so polling stops.

- [ ] **Step 3: Write failing tests** — seed a `ScanSession` + `WorkflowRun` +
  `WorkflowStepResult`s (one `failed`); assert `scan_progress` renders the step rows + the
  failed-coverage banner + severity chips; assert `scan_cancel` POST flips status to
  `cancelled`. Run, make pass.

- [ ] **Step 4: Commit** on `dev`: `feat: mvp scan detail + HTMX live progress + stop`

---

## Task 6: Scans history list

**Files:**
- Modify: `apps/mvp/views.py` (`scans`), `apps/mvp/urls.py`
- Create: `apps/mvp/templates/mvp/scans.html`
- Test: `tests/unit/test_mvp_views.py`

**Interfaces:**
- Consumes: `ScanSession` (filter by `?domain=`/`?status=`, paginated).
- Produces: route `mvp:scans`.

- [ ] **Step 1: Write `scans`** — `ScanSession.objects` ordered newest-first, optional
  `domain`/`status` GET filters, Django `Paginator`.
- [ ] **Step 2: Template** — a table linking each row to `mvp:scan-detail`.
- [ ] **Step 3: Failing test** — seed 3 sessions across 2 statuses; assert the list renders and
  `?status=completed` filters. Run, make pass.
- [ ] **Step 4: Commit** on `dev`: `feat: mvp scans history list`

---

## Task 7: Change-password flow (`must_change_password`)

**Files:**
- Create: `apps/mvp/middleware.py`, `apps/mvp/templates/mvp/change_password.html`
- Modify: `apps/mvp/views.py` (`change_password`), `apps/mvp/urls.py`,
  `openeasd/settings/base.py` (MIDDLEWARE)
- Test: `tests/unit/test_mvp_views.py`

**Interfaces:**
- Consumes: `UserProfile.must_change_password` (`apps/core/console/dashboard`).
- Produces: route `mvp:change-password`; `MustChangePasswordMiddleware`.

- [ ] **Step 1: Write `MustChangePasswordMiddleware`** — for an authenticated user whose
  `profile.must_change_password` is True, redirect any non-(`/change-password/`,`/logout/`,
  `/static/`) request to `mvp:change-password`. (This replaces the Ninja `JWTAuth` +
  `_report_auth_required` enforcement.)
- [ ] **Step 2: Write `change_password`** (GET form + POST): validate with Django's
  `PasswordChangeForm`, reject > 128 chars (mirror the removed API rule), on success clear the
  flag + `update_session_auth_hash`.
- [ ] **Step 3: Failing tests** — a flagged user is redirected to change-password from the
  dashboard; a valid change clears the flag + stops redirecting; a > 128-char password is
  rejected. Run, make pass.
- [ ] **Step 4: Commit** on `dev`: `feat: mvp forced change-password flow + middleware`

---

## Task 8: Rewrite `openeasd/urls.py` — drop /api/ + SPA catch-all

**Files:**
- Modify: `openeasd/urls.py`
- Test: `tests/unit/test_mvp_views.py` (routing asserts)

**Interfaces:**
- Consumes: `apps.mvp.urls`, `auth_views`, the plain `health`/`metrics` views.
- Produces: the end-state URL conf (mvp at root).

- [ ] **Step 1: Rewrite `urls.py`** to the spec §4.5 end state (remove
  `from apps.core.console.api.ninja import api`, the `path("api/", api.urls)`, and the `spa`
  view + SPA catch-all; move `apps.mvp.urls` from `/app/` to root `""`; add a `catch_all` →
  `redirect("mvp:dashboard")` and a `favicon` 204). Keep `health`, `metrics`, `admin`,
  `reports`, `login`, `logout`, `static(MEDIA_URL…)`.
- [ ] **Step 2: Failing tests** — `/` resolves to `mvp:dashboard`; `/api/` and `/api/docs`
  return 404; `/health/` still returns 200 JSON with `version`. Run, make pass. Update the
  Task-1 tests that used the `/app/` prefix to root paths.
- [ ] **Step 3: Commit** on `dev`: `feat: serve mvp at root; remove /api/ + SPA catch-all from urls`

---

## Task 9: Reports — CSV session-only; remove PDF

**Files:**
- Modify: `apps/core/console/reports/views.py`, `apps/core/console/reports/urls.py`
- Delete: the PDF report template(s), the WeasyPrint `_render_pdf` + `export_scan_pdf` + PDF-only helpers
- Test: `tests/unit/test_reports.py` (trim), `tests/unit/test_mvp_views.py`

**Interfaces:**
- Produces: `/reports/<uuid>/csv/` under session auth only; no `/pdf/` route.

- [ ] **Step 1: Replace `_report_auth_required` with Django's `login_required`** on
  `export_findings_csv` (plus the `must_change_password` check, now covered by the middleware
  from Task 7 — so a plain `@login_required` suffices). Remove the Bearer-token branch.
- [ ] **Step 2: Delete `export_scan_pdf`**, the `/pdf/` url, the PDF template(s), and any
  helper only the PDF used (keep every helper CSV shares). Leave the CSV content logic intact.
- [ ] **Step 3: Trim `tests/unit/test_reports.py`** — drop the PDF/WeasyPrint tests; keep the
  CSV content/structure/min-severity tests; change their auth setup from Bearer to
  `client.login`. Add an assert that `/reports/<uuid>/pdf/` is 404.
- [ ] **Step 4: Run** `uv run pytest tests/unit/test_reports.py tests/unit/test_mvp_views.py -v`; make pass.
- [ ] **Step 5: Commit** on `dev`: `feat: reports CSV session-only; remove PDF/WeasyPrint export`

---

## Task 10: Remove the Ninja API + JWT + stale deps

**Files:**
- Delete: `apps/core/console/api/` (entire package), `tests/test_api_endpoints.py`,
  `tests/unit/test_api_*.py`
- Modify: `openeasd/settings/base.py` (drop ninja/jwt apps + JWT config), `pyproject.toml`,
  `uv.lock`
- Test: `tests/unit/test_settings_security.py` (still green), the full suite

**Interfaces:** none produced; this is removal.

- [ ] **Step 1: Delete the api package + its tests.** Grep for stray imports:
  `grep -rn "console.api\|NinjaAPI\|ninja_jwt\|JWTAuth\|simplejwt" apps/ openeasd/ tests/` — fix
  every hit (e.g. `apps/core/console/api/ratelimit.py` moves in Task 11; the
  `OutstandingToken`/`BlacklistedToken` logout path is gone).
- [ ] **Step 2: Settings** — remove `ninja`/`ninja_jwt`/`rest_framework_simplejwt` from
  INSTALLED_APPS and the NINJA_JWT / SIMPLE_JWT config block.
- [ ] **Step 3: Deps** — remove `django-ninja`, `django-ninja-jwt` from `pyproject.toml`;
  remove `pyjwt` only if `grep -rn "import jwt\|pyjwt"` finds no remaining use; then
  `uv lock` and `uv sync --group dev`.
- [ ] **Step 4: Run the fast suite** `uv run pytest tests/ --ignore=tests/unit/test_domain_security.py`;
  fix fallout. Re-check the coverage gate (`--cov-fail-under=80`) — if removing well-tested API
  code dropped it, note it (do **not** lower the gate without calling it out).
- [ ] **Step 5: Commit** on `dev`: `fix: remove Django-Ninja REST API + JWT auth + deps`

---

## Task 11: Retarget the login rate-limiter to `/login/`

**Files:**
- Modify: `apps/core/console/api/ratelimit.py` → move to `apps/mvp/ratelimit.py` (or keep path),
  `openeasd/settings/base.py` (MIDDLEWARE path), `tests/unit/test_login_ratelimit.py`
- Test: `tests/unit/test_login_ratelimit.py`

**Interfaces:**
- Consumes: the `LoginThrottle` model (unchanged).
- Produces: `LoginRateLimitMiddleware` keyed on failed `POST /login/`.

- [ ] **Step 1: Decision + move.** `LoginRateLimitMiddleware` lived under the deleted api
  package. Move it to `apps/mvp/ratelimit.py` and change its target from `POST /api/token/pair`
  to `POST /login/` (a failed Django login redirects/re-renders with no auth'd user; detect
  failure via the response + `request.user.is_authenticated`). Keep the `LoginThrottle` model +
  the rightmost-XFF keying.
- [ ] **Step 2: Update `tests/unit/test_login_ratelimit.py`** to drive `/login/` instead of
  `/api/token/pair`. Run, make pass.
- [ ] **Step 3: Commit** on `dev`: `feat: retarget login rate-limiter to the session /login/ endpoint`

---

## Task 12: Delete `frontend/`; trim CI + Dockerfile

**Files:**
- Delete: `frontend/` (entire directory)
- Modify: `.github/workflows/ci.yml`, `Dockerfile`
- Test: CI config validity (lint), a local `uv run pytest` smoke

**Interfaces:** none.

- [ ] **Step 1: Delete `frontend/`.** Grep for references:
  `grep -rn "frontend/dist\|frontend/src\|npm\|vite" openeasd/ apps/ Dockerfile .github/ justfile Makefile` — fix each (the `spa()` view + SPA static are already gone after Task 8).
- [ ] **Step 2: CI** — remove the `frontend` job from `ci.yml` and any `needs: [frontend]`;
  remove the WeasyPrint system libs (`libcairo2-dev gcc libpango-1.0-0 libpangocairo-1.0-0
  libgdk-pixbuf-2.0-0`) from the `test` job (no longer needed without PDF). Keep the
  `postgres:17-alpine` service.
- [ ] **Step 3: Dockerfile** — remove the `frontend-builder` node stage (lines ~15–22) and the
  `COPY --from=frontend-builder /build/frontend/dist/ frontend/dist/` line. `collectstatic` now
  gathers `apps/mvp/static/` only.
- [ ] **Step 4: Verify** — `uv run manage.py collectstatic --noinput --dry-run` succeeds;
  `just ci` (or the fast suite) passes locally.
- [ ] **Step 5: Commit** on `dev`: `fix: delete React frontend; drop CI frontend job + Docker node stage`

---

## Task 13: Single-image entrypoint — embedded Postgres + supervisor

**Files:**
- Create: `docker/entrypoint-singleimage.sh`, `docker/Procfile`
- Modify: `Dockerfile` (single-image target installing postgresql + a supervisor)
- Test: `tests/unit/test_entrypoint_singleimage.py` (pure-bash-logic bits) + a manual smoke note

**Interfaces:**
- Produces: a single image whose entrypoint brings up Postgres → migrate → web + worker.

- [ ] **Step 1: Write `entrypoint-singleimage.sh`** — idempotent: if `$PGDATA` is empty run
  `initdb` + start Postgres + `createuser`/`createdb` from `DB_*`; else just start Postgres.
  Wait for `pg_isready` (reuse the existing DB-wait). Then run the normal role-aware
  `docker-entrypoint.sh` migrate/collectstatic/admin steps, then `exec honcho start` over the
  `Procfile`. Forward SIGTERM to all children for clean shutdown.
```bash
# Procfile
web: gunicorn openeasd.wsgi:application --bind 0.0.0.0:8000 --workers 2
worker: python manage.py dbos_worker
```
- [ ] **Step 2: Dockerfile single-image target** — on the Ubuntu worker base, `apt-get install
  postgresql honcho` (or `pip install honcho`); set `PGDATA=/data/pgdata`, `VOLUME /data`;
  `ENTRYPOINT ["docker/entrypoint-singleimage.sh"]`. Keep `NET_RAW` guidance in docs.
- [ ] **Step 3: Tests** — unit-test any pure helper you factor out (e.g. a Python
  `should_initdb(path)` used by the script), and add a `docs/OPERATIONS.md` manual smoke:
  `docker run -v openeasd-data:/data ... ` → `/health/` 200 → start a passive scan → reaches a
  terminal status. (A full container smoke is manual; the engine tests already cover scan logic.)
- [ ] **Step 4: Commit** on `dev`: `feat: single-image entrypoint — embedded Postgres + honcho (web+worker)`

---

## Task 14: Compose / k8s + OPERATIONS

**Files:**
- Create: `docker-compose.singleimage.yml` (or a documented `docker run`)
- Modify: `docker-compose.yml` (keep as the 3-service alternative), `docs/OPERATIONS.md`
- Test: compose config lint (`docker compose config`)

- [ ] **Step 1: Single-image compose** — one service, `/data` volume, env from `.env`, ports
  `8000` behind the documented TLS proxy. Keep the existing 3-service compose unchanged as the
  "external Postgres / privilege-separated" path and say so in a header comment.
- [ ] **Step 2: OPERATIONS** — document both deploy shapes, the **mandatory `/data` volume**
  (data loss warning), the single-image privilege-separation tradeoff, and backups via
  in-container `pg_dump`. Decide (and record) whether a single-image **k8s** manifest is in MVP
  scope; if not, note the 3-tier k8s path stays and leave `test_k8s_manifests.py` as-is.
- [ ] **Step 3: Commit** on `dev`: `docs: single-image compose + OPERATIONS (deploy shapes, volume, backups)`

---

## Task 15: Docs + memory

**Files:**
- Modify: `CLAUDE.md`, `docs/03-system.md`, `docs/05-api.md`, `docs/06-coding.md`,
  `docs/04-technical.md` (index the spec), `CHANGELOG.md`, memory
  `feedback_backend_first_frontend_last.md` + `MEMORY.md`

- [ ] **Step 1: CLAUDE.md** — rewrite the **Stack/Frontend**, **URL layout**, **Status**, and
  **Deployment** sections: plain-Django + Bulma/HTMX + session auth; no SPA/Ninja/JWT/PDF;
  single-image + embedded-Postgres deploy (3-tier kept as alt); update the **Tests** table
  (remove API/Vitest rows, add `test_mvp_views`).
- [ ] **Step 2: Doc chain** — `03-system` (UI/edge), `05-api` (now "no REST API — server-
  rendered; CSV export endpoint only"), `06-coding` (view→service pattern, HTMX), and index the
  spec in `04-technical`. `CHANGELOG.md` Unreleased entry (What + Why).
- [ ] **Step 3: Memory** — update `feedback_backend_first_frontend_last` /
  `project_domain_centric_direction` to record the direction change to a plain-Django,
  session-auth, single-admin UI (the "UI-agnostic API-driven" stance no longer holds); add the
  one-line pointer in `MEMORY.md`.
- [ ] **Step 4: Commit** on `dev`: `docs: update CLAUDE.md + doc chain + memory for plain-Django UI`

---

## Self-review notes

- **Spec coverage:** every spec section maps to a task — UI pages (T2–T7), urls (T8), reports/
  CSV+PDF (T9), API/JWT removal (T10), rate-limiter (T11), frontend/CI/Docker (T12),
  single-image (T13–T14), docs/memory (T15). The engine/DBOS/Postgres "not changing" scope is
  honored (no task touches `apps/core/engine/` execution code).
- **Ordering:** T1–T7 build the UI alongside the still-live SPA (prefix `/app/`), so each lands
  green; T8 flips root + removes the SPA edge; T9–T12 remove the old edge; T13–T14 package;
  T15 docs. A reviewer can reject any task independently.
- **Open decisions deferred to execution (ruled in-task, not blocking):** keep/retire the login
  rate-limiter (T11), single-image k8s scope (T14), and whether `pyjwt` is still referenced
  (T10 Step 3).
- **Type consistency:** view/route names are stable (`mvp:dashboard`, `mvp:domain-detail`,
  `mvp:scan-detail`, `mvp:scan-progress`, …) and reused across tasks; the engine service
  signatures (`create_scan_session(domain, triggered_by, workflow, tools)`, `run_scan_task
  (session_id)`) match the live code read during spec authoring.
