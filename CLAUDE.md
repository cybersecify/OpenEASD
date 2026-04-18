# CLAUDE.md — OpenEASD Django Project

External Attack Surface Detection platform. Scans domains for network and
web vulnerabilities using a dynamic workflow engine with auto-registered tools.

## Git workflow
- Solo developer — commit directly to main, no branches or worktrees
- Run `uv run pytest tests/ --ignore=tests/unit/test_domain_security.py` before committing
- Tag before big changes (new libs, refactors, schema changes): `git tag -a v0.x -m "description"`
- If something breaks: `git revert <commit>` or `git reset --hard v0.x` to roll back
- **Versioning:** `0.x` = building/architecture changes, `1.0` = first stable public release
- **Pushing to GitHub (clean history):**
  1. Work locally, commit as often as needed
  2. When stable, squash into one commit: `git reset --soft <last-tag> && git commit -m "v0.x: summary"`
  3. Tag it: `git tag -a v0.x -m "description"`
  4. Push: `git push origin main --tags`

## Commands
- Always use `uv run python` instead of `python` or `python3`
- Always use `uv run manage.py` for Django management commands (e.g. `uv run manage.py check`)
- Always use `uv run pytest` for running tests
- The slow `tests/unit/test_domain_security.py` (41 tests) makes real DNS/RDAP calls — exclude it for fast CI runs:
  `uv run pytest tests/ --ignore=tests/unit/test_domain_security.py`

## Stack

### Backend
- Django 5+ with plain Django views (no DRF, no Celery, no Redis)
- Pure Django REST API under `/api/` — `JsonResponse` only, no third-party API libs
- Huey — lightweight task queue for background scan execution
- `django-apscheduler` for daily automated scans (starts in `SchedulerConfig.ready()`)
- SQLite database (dev), configurable via `DB_NAME` env var

### Frontend (React SPA — new primary UI)
- **React 18 + Vite** — `frontend/` directory, builds to `frontend/dist/`
- Vanilla popstate-based router in `App.jsx` (no react-router)
- CSRF-aware `apiFetch` in `src/api/client.js` — uses session auth + `X-CSRFToken` header
- `useFetch` / `usePolling` hooks for data fetching and live scan status (3s poll)
- Shared components: `Badge`, `Spinner`, `Pagination`, `ConfirmButton`, `Notification`
- Dark theme throughout: bg `#0d1117`, card `#161b22`, border `#30363d`, accent `#30c074`
- **Dev:** Vite proxy forwards `/api/` → Django on port 8000 (no CORS config needed)
- **Prod:** `npm run build` → `frontend/dist/` → served by Django `STATICFILES_DIRS`

### Legacy HTML stack (still intact, runs in parallel)
- HTMX — server-driven UI updates (form submits, polling, partial HTML swaps)
- Alpine.js — client-side UI state (modals, dropdowns, tabs, toggles)
- Tailwind CSS via CDN (no build step)
- Chart.js — visualizations via CDN

### Frontend dev setup
```bash
# Terminal 1 — Django
uv run manage.py runserver

# Terminal 2 — Vite dev server (proxies /api/ to Django)
cd frontend && npm install && npm run dev
# App runs at http://localhost:5173
```

### Frontend rules
- New interactive features → React pages in `frontend/src/pages/`
- New API data → add endpoint to `apps/core/api/views/` + wire in `apps/core/api/urls.py`
- Shared UI primitives → `frontend/src/components/`
- Don't add CORS headers — always use same-origin (Vite proxy in dev, Django serves in prod)
- Legacy HTMX/Alpine/Django-template stack is **retired**. All UI is the React SPA.
- SPA catch-all in `openeasd/urls.py` serves `frontend/dist/index.html` for all non-API paths.
- Run `cd frontend && npm run build` to update the production bundle before deployment.

## Scheduler
- Daily scan runs at `SCAN_DAILY_HOUR:SCAN_DAILY_MINUTE` (uses `TIME_ZONE` in settings, default 02:00)
- Configured via env vars: `SCAN_DAILY_HOUR`, `SCAN_DAILY_MINUTE`
- Disable on extra workers via `SCHEDULER_ENABLED=False` (for multi-worker gunicorn)
- Job history visible in Django admin under "Django APScheduler"
- Scheduler code lives in `apps/core/scheduler/scheduler.py`
- Started by `apps/core/scheduler/apps.py` → `SchedulerConfig.ready()`
- Guard prevents double-start in dev server (checks `RUN_MAIN` env var)

## External binary tools

ProjectDiscovery tools installed via `pdtm` at `~/.pdtm/go/bin/`:
- `subfinder`, `dnsx`, `naabu`, `httpx`, `nuclei`

System binary:
- `nmap` (Homebrew at `/opt/homebrew/bin/nmap`)

Tool paths are configurable via `TOOL_SUBFINDER`, `TOOL_DNSX`, `TOOL_NAABU`, `TOOL_HTTPX`, `TOOL_NMAP`, `TOOL_NUCLEI` env vars.

## Architecture

### Core infrastructure — `apps/core/` (13 sub-apps)

| App | Label | Purpose |
|---|---|---|
| `dashboard/` | `core` | Dashboard page, health check (legacy HTML) |
| `domains/` | `domains` | Domain model, CRUD views |
| `assets/` | `assets` | Network assets: Subdomain, IPAddress, Port |
| `web_assets/` | `web_assets` | Web assets: URL |
| `service_detection/` | `service_detection` | Enriches Port.service + Port.is_web via nmap -sV |
| `findings/` | `findings` | Unified Finding model — all tools write here |
| `scans/` | `scans` | ScanSession, ScanDelta, pipeline orchestrator |
| `workflows/` | `workflow` | Workflow CRUD, dynamic runner, tool registry |
| `scheduler/` | `scheduler` | APScheduler setup, daily/weekly scans, stuck scan watchdog |
| `notifications/` | `alerts` | Slack/Teams alert dispatcher |
| `insights/` | `insights` | ScanSummary, FindingTypeSummary, charts |
| `reports/` | `reports` | CSV + PDF export |
| `api/` | — | Pure Django REST API — `JsonResponse` views, serializers, auth decorator |

### REST API module — `apps/core/api/`

```
apps/core/api/
    __init__.py
    decorators.py     — api_login_required (returns 401 JSON, not redirect)
    serializers.py    — serialize_* functions + api_response() helper
    urls.py           — all /api/ routes
    views/
        auth.py       — /api/auth/user|login|logout/
        dashboard.py  — /api/dashboard/
        domains.py    — /api/domains/ CRUD
        scans.py      — /api/scans/ + findings + scheduled jobs
        workflows.py  — /api/workflows/ CRUD + /tools/ registry endpoint
        insights.py   — /api/insights/
```

**Standard response envelope:**
```json
{"ok": true, "data": {...}, "errors": null, "pagination": {...}}
```

**Auth:** Session-based (no tokens). React sends `X-CSRFToken` header from `csrftoken` cookie.

**Adding a new API endpoint:**
1. Add view function to the relevant `apps/core/api/views/*.py`
2. Wire URL in `apps/core/api/urls.py`
3. Consume in `frontend/src/api/client.js` or a page component

### Tool auto-registration

Tools self-register via `AppConfig.tool_meta`. **No core files need editing when adding a new tool** (except `settings.INSTALLED_APPS`).

```python
# Example: apps/my_tool/apps.py
class MyToolConfig(AppConfig):
    name = "apps.my_tool"
    label = "my_tool"
    verbose_name = "My Tool"
    tool_meta = {
        "label": "My Tool",
        "runner": "apps.my_tool.scanner.run_my_tool",
        "phase": 7,
        "requires": ["naabu"],
        "produces_findings": True,
    }
```

The registry (`apps/core/workflows/registry.py`) auto-discovers all `tool_meta` at startup and provides:
- `get_tool_choices()` — for forms and UI
- `get_tool_runners()` — for workflow execution
- `get_tool_phases()` — for ordering
- `get_tool_requires()` — for dependency validation
- `get_source_choices()` — for finding source filtering

### Tool apps (11 registered tools)

| App | Phase | produces_findings | Description |
|---|---|---|---|
| `apps/domain_security/` | 1 | Yes | DNS, email, RDAP checks |
| `apps/subfinder/` | 2 | No | Passive subdomain enumeration |
| `apps/dnsx/` | 3 | No | DNS resolution, public IP filtering |
| `apps/naabu/` | 4 | No | Port scanning (top 100 TCP) |
| `apps/core/service_detection/` | 5 | No | nmap -sV enriches Port.service + is_web |
| `apps/httpx/` | 6 | No | Web probing, URL discovery |
| `apps/nmap/` | 7 | Yes | NSE vulners CVE scan (non-web ports) |
| `apps/tls_checker/` | 7 | Yes | TLS/cert analysis (all ports) |
| `apps/ssh_checker/` | 7 | Yes | SSH config analysis |
| `apps/nuclei/` | 8 | Yes | Web vuln scan (community templates) |
| `apps/web_checker/` | 8 | Yes | Security headers, cookies, CORS |

### Tool app structure
```
apps/<tool>/
    apps.py         — AppConfig with tool_meta (self-registration)
    models.py       — empty (writes to apps/core/assets/ and apps/core/findings/)
    scanner.py      — thin orchestrator: collect → analyze → save
    collector.py    — runs binary or probes, returns raw data (no DB)
    analyzer.py     — parses raw data, builds shared Asset/Finding objects
```

## Scan pipeline

All scans run through the **dynamic workflow system**. The default "Full Scan"
workflow executes all 11 tools in phase order. Custom workflows can include
any subset of tools.

```
Phase 1  domain_security    → Finding (DNS/email/RDAP)
Phase 2  subfinder          → Subdomain (passive enumeration)
Phase 3  dnsx               → IPAddress (public-only filter)
Phase 4  naabu              → Port (top 100 TCP scan)
Phase 5  service_detection  → enriches Port.service + Port.is_web
Phase 6  httpx              → URL (web probing, CDN-aware via SNI)
Phase 7  nmap               → Finding (CVEs on non-web ports, is_web=False)
Phase 7  tls_checker        → Finding (cipher/cert/protocol on all ports)
Phase 7  ssh_checker        → Finding (SSH config on service="ssh" ports)
Phase 8  nuclei             → Finding (web vulns via templates on URLs)
Phase 8  web_checker        → Finding (headers, cookies, CORS on URLs)
```

### Scan flow
```
create_scan_session(domain)          # auto-assigns default workflow
  → run_scan_task(session_id)        # Huey async task
    → run_scan(session_id)           # sets status="running"
      → _run_via_workflow(session)   # creates WorkflowRun, calls run_workflow()
        → run_workflow(run_id)       # loops enabled tools, records StepResults
      → _finalize_session(session)   # count findings, deltas, insights, alerts
```

### Key design rules
1. **Tools never import from each other.** Shared data flows through `apps/core/assets/`, `apps/core/web_assets/`, and `apps/core/findings/`.
2. **Tools self-register.** Add `tool_meta` to AppConfig + add to `INSTALLED_APPS`. No other core files to touch.
3. **Port.is_web** classifies ports. Set by `service_detection` (Phase 5) based on nmap -sV service name. Used by nmap to skip web ports, by tls_checker for branching.
4. **dnsx filters to public IPs only.** Private/loopback/link-local/AWS metadata IPs dropped.
5. **httpx feeds subdomain:port pairs, not IP:port pairs.** Cloudflare/CDN-fronted services need SNI matching.
6. **nmap only scans non-web ports** (`Port.objects.filter(is_web=False)`).
7. **Asset deletion cascades:** Subdomain → IPAddress → Port → URL. Deleting a Domain wipes all session data.
8. **Delta detection** compares ALL findings between current and previous scan for the same domain.

## Unified Finding model

`apps/core/findings/Finding` — all tools write to it:

```python
class Finding(models.Model):
    session     = FK(ScanSession)
    source      = CharField()      # auto-registered from tool_meta
    check_type  = CharField()      # tool-specific: "dns", "cve", "weak_ssh_kex", etc.
    severity    = "critical" | "high" | "medium" | "low" | "info"
    title       = CharField()
    description = TextField()
    remediation = TextField()
    target      = CharField()      # hostname or IP:port
    port        = FK(Port, null=True)
    url         = FK(web_assets.URL, null=True)
    extra       = JSONField()      # tool-specific: cve, cvss_score, cipher_name, etc.
```

**SQLite quirk:** Don't use `Max("extra__cvss_score")` or other aggregations on JSON-extracted fields — Django/SQLite fails. Group in Python instead.

## URL layout

### REST API (`/api/`)
```
GET  /api/auth/user/                      — current user info
POST /api/auth/login/                     — session login
POST /api/auth/logout/                    — session logout
GET  /api/dashboard/                      — KPIs, domain status, urgent findings
GET  /api/domains/                        — list domains (enriched)
POST /api/domains/                        — add domain
POST /api/domains/<pk>/toggle/            — activate/deactivate
POST /api/domains/<pk>/delete/            — delete domain + all scan data
GET  /api/scans/                          — paginated scan list (?domain=&status=&page=)
POST /api/scans/start/                    — start/schedule scan
GET  /api/scans/<uuid>/                   — full scan detail (assets + findings)
GET  /api/scans/<uuid>/status/            — lightweight status (React polls every 3s)
POST /api/scans/<uuid>/stop/              — cancel running scan
POST /api/scans/<uuid>/delete/            — delete scan session
GET  /api/scans/findings/                 — paginated findings (?severity=&domain=&status=&source=)
POST /api/scans/findings/<id>/status/     — update finding lifecycle status
GET  /api/scheduled/                      — scheduled jobs list
POST /api/scheduled/<job_id>/cancel/      — cancel scheduled job
GET  /api/workflows/                      — list workflows
POST /api/workflows/create/               — create workflow
GET  /api/workflows/tools/                — all registered tool choices (for create form)
GET  /api/workflows/<pk>/                 — workflow detail + tool_steps + recent runs
POST /api/workflows/<pk>/update/          — update workflow name/tools
POST /api/workflows/<pk>/delete/          — delete workflow
POST /api/workflows/<pk>/steps/<tool>/toggle/ — toggle single tool step
GET  /api/insights/                       — trends, top hosts, asset growth, KPIs
```

### Legacy HTML routes (still active)
- `/` → dashboard (Django template)
- `/health/` → health check
- `/domains/` → domain CRUD
- `/scans/` → scan list
- `/scans/start/` → start scan
- `/scans/<uuid>/` → scan detail with HTMX polling
- `/scans/findings/` → finding list
- `/scans/scheduled/` → scheduled jobs
- `/workflows/` → workflow list/create/detail
- `/insights/` → trends, charts
- `/reports/<uuid>/csv/` → CSV export
- `/reports/<uuid>/pdf/` → PDF export
- `/admin/` → Django admin

## Tests

| File | Tests | Notes |
|---|---|---|
| `tests/unit/test_alerts.py` | 7 | Slack/Teams dispatcher |
| `tests/unit/test_assets.py` | 13 | Asset model constraints, FK chains, cascade delete |
| `tests/unit/test_core.py` | 10 | Dashboard view |
| `tests/unit/test_dnsx.py` | 20 | Public IP filter, analyzer, scanner |
| `tests/unit/test_domain_security.py` | 41 | DNS/email/RDAP — **slow, real network** |
| `tests/unit/test_domains.py` | 15 | Domain CRUD |
| `tests/unit/test_httpx.py` | 11 | JSON parser, Port lookup, Subdomain link |
| `tests/unit/test_insights.py` | 11 | Insights builder + view |
| `tests/unit/test_naabu.py` | 9 | JSON parser, FK to IPAddress |
| `tests/unit/test_nmap.py` | 21 | Severity mapping, vulners XML parser, web/non-web exclusion |
| `tests/unit/test_scans.py` | 55 | ScanSession, scheduling, scan_start views |
| `tests/unit/test_subfinder.py` | 11 | JSON parser, dedup, hostname normalization |
| `tests/unit/test_tls_checker.py` | 77 | Cert parsing, ciphers, protocols, HSTS, collector, scanner |
| `tests/unit/test_ssh_checker.py` | 33 | SSH probe, host key, kex/cipher/MAC, auth, collector |
| `tests/unit/test_nuclei.py` | 25 | CVE parsing, severity, dedup, URL linking, collector |
| `tests/unit/test_web_checker.py` | 34 | Headers, cookies, CORS, disclosure, collector |
| `tests/unit/test_service_detection.py` | 16 | XML parsing, Port enrichment, is_web |
| `tests/integration/test_scan_flow.py` | 13 | Full pipeline (mocked) + delete cascade |

**Total: ~555 tests** (~514 fast + 41 slow domain_security)
