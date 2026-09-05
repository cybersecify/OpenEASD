# `local` branch — DBOS + PostgreSQL re-platforming

This branch re-platforms OpenEASD's **persistence** (SQLite → PostgreSQL) and
**execution** (Django-Q → DBOS durable workflows). It deliberately does NOT
rewrite the database-agnostic domain code (the 26 tool collectors/analyzers,
the Finding model, the API schemas) — those work unchanged on Postgres.

## Why

- **Durable scans.** A scan is a DBOS workflow whose phases are checkpointed
  steps. A worker crash/restart RESUMES the scan at the phase it was in,
  instead of `reap_stuck_scans` marking it failed and losing the work.
- **Real concurrency.** Postgres handles concurrent writers, so scans no longer
  need the SQLite single-writer lock (`workers: 1`). The scan queue runs at
  `DBOS_SCAN_CONCURRENCY` (default 2).
- **Exactly-once + retries + observability** come from DBOS for free
  (deduplicated enqueue by session id, step retries, workflow tracing).

## What changed (done + verified)

- **`openeasd/settings.py`** — `DATABASES` → PostgreSQL (`DB_*` env vars or
  `DATABASE_URL`); DBOS settings (`DBOS_DATABASE_URL`, `DBOS_APP_NAME`,
  `DBOS_SCAN_CONCURRENCY`, `SCAN_STEP_TIMEOUT`). `psycopg[binary]`, `dbos`,
  `dj-database-url` added to deps.
- **`apps/core/durable/`** (new) — `dbos_app.py` (engine/client config, system
  DB URL derived from Django's DATABASES, shared `dbos` schema),
  `workflows.py` (`run_scan`, `ai_triage`, `agent_step` durable workflows +
  checkpointed steps + enqueue helpers), `management/commands/dbos_worker.py`
  (replaces `qcluster`).
- **`apps/core/workflows/runner.py`** — extracted `resolve_phase_groups()` +
  `run_one_phase_group()` (shared by `run_workflow` and the DBOS steps);
  `run_workflow` behavior unchanged.
- **`apps/core/scans/pipeline.py`** — added DBOS entry points:
  `mark_session_running`, `prepare_session_assets`, `phase_groups_for_session`,
  `run_phase_group_for_session`, `finalize_session_by_id`.
- **`apps/core/scans/tasks.py`** / **`apps/core/ai/tasks.py`** — enqueue via
  DBOS instead of `async_task`.

**Verified:** `manage.py migrate` applies cleanly to Postgres; the DBOS engine
launches, applies its system schema, and registers the `scans` queue; a full
`run_scan` workflow executes end-to-end on Postgres (26 tool steps → session
`completed`, tools mocked for offline speed).

## What remains (not done on this branch yet)

1. **Test suite Postgres-compat pass (~1600 tests).** Two classes of change:
   (a) threaded runner tests need `transactional_db` (Postgres closes the
   pytest transaction connection when phase-executor threads call
   `close_old_connections()` — correct in prod, not under a single test
   transaction); (b) tests that patch `django_q.tasks.async_task` must patch the
   DBOS enqueue helpers instead. ~16/34 runner tests currently fail for reason (a).
2. **Scheduler migration — core jobs DONE.** The unattended-scanning backbone
   is now DBOS `@scheduled` workflows in `apps/core/durable/workflows.py`:
   `scheduled_daily_scan`, `scheduled_monitoring_sweep` (replaces per-domain
   Django-Q timers with one due-ness sweep — `run_due_monitoring_scans`),
   `scheduled_watchdog`, `scheduled_token_purge` — all gated by
   `SCHEDULED_SCANS_ENABLED`, registered when `dbos_worker` imports the module
   (verified: 4 pollers register; sweep scans only due domains).
   `setup_core_schedules` / `sync_domain_monitoring_jobs` are now no-ops.
   **Remaining Django-Q holdout:** the user-created one-time/recurring scan
   endpoints (`_schedule_once` / `_schedule_recurring` / `list_scheduled` /
   `cancel_scheduled` in `scans/api.py`, and the domain-delete schedule cleanup
   in `domains/api.py`). Migrate these to DBOS `create_schedule` +
   delayed-enqueue to drop `django-q2` entirely.
3. **Deployment.** `docker-entrypoint.sh` (add Postgres wait + `dbos_worker`
   instead of `qcluster`), `docker-compose` / `k8s/` (add a Postgres service /
   StatefulSet), CI (Postgres service container). None updated yet.
4. **AI orchestration chain** re-verification under DBOS (logic ported; the
   chain hooks now enqueue DBOS `agent_step` workflows).

## Run it locally

```bash
# Postgres (this branch was verified against):
docker run -d --name openeasd-pg -e POSTGRES_PASSWORD=openeasd \
  -e POSTGRES_USER=openeasd -e POSTGRES_DB=openeasd -p 5433:5432 postgres:17-alpine

export DB_HOST=127.0.0.1 DB_PORT=5433 DB_NAME=openeasd DB_USER=openeasd DB_PASSWORD=openeasd
uv run manage.py migrate
uv run manage.py runserver 8001      # web (enqueues via DBOSClient)
uv run manage.py dbos_worker         # worker (executes durable workflows)
```
