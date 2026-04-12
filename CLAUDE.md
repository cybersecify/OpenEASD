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
- Django 5+ with plain Django views (no DRF, no Celery, no Redis)
- HTMX — server-driven UI updates (form submits, polling, partial HTML swaps)
- Alpine.js — client-side UI state (modals, dropdowns, tabs, toggles, local form state)
- Chart.js — visualizations, loaded via CDN only on pages that need it
- Tailwind CSS via CDN (no build step)
- Huey — lightweight task queue for background scan execution
- `django-apscheduler` for daily automated scans (starts in `SchedulerConfig.ready()`)
- SQLite database (dev), configurable via `DB_NAME` env var

### Frontend rules
- Reach for **Alpine.js first** for client-side interactivity
- Use **HTMX** when the server needs to compute/return new HTML
- Load page-specific JS (Chart.js, etc.) inside the page template, not `base.html`

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

### Core infrastructure — `apps/core/` (12 sub-apps)

| App | Label | Purpose |
|---|---|---|
| `dashboard/` | `core` | Dashboard page, health check |
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
- `/` → dashboard
- `/health/` → health check
- `/domains/` → domain CRUD
- `/scans/` → scan list
- `/scans/start/` → start scan (domain + workflow selection)
- `/scans/<uuid>/` → scan detail with live HTMX polling
- `/scans/findings/` → unified finding list (filters: severity, session, domain)
- `/scans/scheduled/` → scheduled jobs list
- `/workflows/` → workflow list/create/detail (with dependency validation)
- `/insights/` → trends, charts, tool breakdown
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

**Total: 381 tests** (340 fast + 41 slow domain_security)
