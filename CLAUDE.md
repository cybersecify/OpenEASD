# CLAUDE.md — OpenEASD Django Project

## Commands
- Always use `uv run python` instead of `python` or `python3`
- Always use `uv run manage.py` for Django management commands (e.g. `uv run manage.py check`)
- Always use `uv run pytest` for running tests

## Stack
- Django 5+ with plain Django views (no DRF, no Celery, no Redis)
- HTMX for dynamic frontend interactions
- `threading.Thread` for background scan execution
- `django-apscheduler` for daily automated scans (starts in `DashboardConfig.ready()`)
- SQLite database (dev), configurable via `DB_NAME` env var
- Tailwind CSS via CDN (no build step)

## Scheduler
- Daily scan runs at `SCAN_DAILY_HOUR:SCAN_DAILY_MINUTE` (uses `TIME_ZONE` in settings, default 02:00)
- Configured via env vars: `SCAN_DAILY_HOUR`, `SCAN_DAILY_MINUTE`
- Disable on extra workers via `SCHEDULER_ENABLED=False` (for multi-worker gunicorn)
- Job history visible in Django admin under "Django APScheduler"
- Scheduler code lives in `apps/core/scheduler/scheduler.py`
- Started by `apps/core/dashboard/apps.py` → `DashboardConfig.ready()`
- Guard prevents double-start in dev server (checks `RUN_MAIN` env var)

## Project structure

### Core infrastructure — `apps/core/` namespace
- `apps/core/dashboard/` — dashboard, health check, scheduler startup (`label=core`)
- `apps/core/assets/` — shared asset models (Subdomain, IPAddress, Port, URL, Technology, Certificate)
- `apps/core/scans/` — ScanSession + ScanDelta models, orchestrator (`tasks.py`), views, forms
- `apps/core/domains/` — Domain model, CRUD views
- `apps/core/workflows/` — Workflow + WorkflowStep models, runner, views (`label=workflow`)
- `apps/core/scheduler/` — APScheduler setup (`get_scheduler`, `start_scheduler`)
- `apps/core/notifications/` — Alert model, Slack/Teams dispatcher (`label=alerts`)
- `apps/core/insights/` — ScanSummary, FindingTypeSummary, builder
- `apps/core/reports/` — placeholder for future PDF/CSV export

**Note on `label`:** Moved apps keep their original `app_label` (e.g. `scans`, `alerts`, `workflow`, `core`) so existing migrations and ForeignKey string references stay valid.

### Tool apps

#### Active (Pattern 1 — custom Python scripts)
- `apps/domain_security/` — DNS, email, RDAP checks (scanner.py + checks/ subpackage)

#### Disabled (Pattern 2 — OSS binary tools)
These apps exist in the repo but are commented out in `settings.INSTALLED_APPS`, `apps/core/workflows/models.py` TOOL_CHOICES, and `apps/core/workflows/runner.py` _TOOL_RUNNERS. Uncomment all three to re-enable.
- `apps/subfinder/` — Subdomain model + subfinder binary scanner
- `apps/naabu/` — PortResult model + naabu binary scanner
- `apps/nmap/` — ServiceResult model + nmap binary scanner
- `apps/nuclei/` — NucleiFinding model + nuclei binary scanner
- `apps/ssl_checker/` — SSLFinding model + SSL certificate scanner

### Tool app structure (Pattern 2)
```
apps/<tool>/
    models.py       — Finding model
    scanner.py      — thin orchestrator: collect → analyze → bulk_create
    collector.py    — runs binary, returns raw data (no DB)
    analyzer.py     — parses raw data, builds model objects (no DB)
```

## URL layout
- `/` → dashboard
- `/health/` → health check
- `/domains/` → domain CRUD
- `/scans/` → scan list
- `/scans/start/` → start new scan (now / once / recurring)
- `/scans/<uuid>/` → scan detail with live HTMX polling
- `/scans/<uuid>/status/` → HTMX polling fragment
- `/scans/vulnerabilities/` → finding list
- `/scans/scheduled/` → scheduled jobs list
- `/workflows/` → workflow list/create/detail
- `/insights/` → trends and summaries
- `/admin/` → Django admin
