# CLAUDE.md — OpenEASD Django Project

## Commands
- Always use `uv run python` instead of `python` or `python3`
- Always use `uv run manage.py` for Django management commands (e.g. `uv run manage.py check`)
- Always use `uv run pytest` for running tests

## Stack
- Django 5+ with plain Django views (no DRF, no Celery, no Redis)
- HTMX for dynamic frontend interactions
- `threading.Thread` for background scan execution
- `django-apscheduler` for daily automated scans (starts in `CoreConfig.ready()`)
- SQLite database (dev), configurable via `DB_NAME` env var
- Tailwind CSS via CDN (no build step)

## Scheduler
- Daily scan runs at `SCAN_DAILY_HOUR:SCAN_DAILY_MINUTE` UTC (default 02:00)
- Configured via env vars: `SCAN_DAILY_HOUR`, `SCAN_DAILY_MINUTE`
- Job history visible in Django admin under "Django APScheduler"
- Scheduler starts in `apps/core/apps.py` → `CoreConfig.ready()`
- Guard prevents double-start in dev server (checks `RUN_MAIN` env var)

## Project structure
- `apps/core/` — dashboard and health check views
- `apps/scans/` — scan management views, models, tasks, forms
- `templates/` — all HTML templates (base, pages, partials)
- `src/` — scanning engine (tool wrappers, modules, parsers)

## URL layout
- `/` → dashboard
- `/scans/` → scan list
- `/scans/start/` → start new scan
- `/scans/<id>/` → scan detail with live HTMX polling
- `/scans/<id>/status/` → HTMX polling fragment (returns partial HTML)
- `/scans/vulnerabilities/` → vulnerability list
- `/health/` → health check
- `/admin/` → Django admin
