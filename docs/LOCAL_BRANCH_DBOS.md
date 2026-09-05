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

1. **Test suite Postgres-compat pass — DONE.** From 66 failing on the first
   Postgres run to green. What changed:
   - Threaded runner + concurrency tests → `transactional_db` (Postgres closes
     the pytest transaction connection when phase-executor threads call
     `close_old_connections()` — correct in prod, not under one test transaction).
   - `async_task` mocks repointed to the stable seams (`run_scan_task`,
     `enqueue_agent_step`, `enqueue_triage`); `_run_triage_task` →
     `run_triage_and_summaries`.
   - `test_qcluster_config` rewritten for the DBOS/`SCAN_TASK_TIMEOUT` invariants;
     `test_monitoring` rewritten for the `run_due_monitoring_scans` sweep;
     `test_scheduler` master-switch tests moved to the extracted
     `run_*_if_enabled` helpers; `_parse_schedule`/domain-delete tests moved to
     `ScheduledScan`.
   - **Real fix, not just tests:** the duplicate-scan guard didn't hold under
     concurrency on Postgres (SQLite's single-writer had masked it), so scan
     creation added a partial unique constraint `uniq_active_scan_per_domain`
     (one pending/running non-subscan per domain); the existing
     `except DatabaseError` fallback turns the violation into "scan already active".
2. **Scheduler migration — DONE; `django-q2` removed entirely.** All scheduling
   is now DBOS `@scheduled` workflows in `apps/core/durable/workflows.py`
   (5 pollers, all gated by `SCHEDULED_SCANS_ENABLED`, registered when
   `dbos_worker` imports the module):
   - `scheduled_daily_scan` (cron from `SCAN_DAILY_HOUR/MINUTE`)
   - `scheduled_monitoring_sweep` → `run_due_monitoring_scans` (one sweep vs a
     Django-Q timer per domain; due-ness from scan history)
   - `scheduled_user_scans_sweep` → `run_due_user_scans` — fires user-created
     one-time/recurring scans stored in the new **`ScheduledScan`** model
     (Postgres-native): one-time deleted after firing, recurring advanced via
     `croniter`. Replaces the Django-Q ONCE/CRON `Schedule` rows.
   - `scheduled_watchdog` + `scheduled_token_purge`

   `scans/api.py` (`_schedule_once`/`_schedule_recurring`/`list_scheduled`/
   `cancel_scheduled`/`_parse_schedule`) and `domains/api.py` (delete cleanup)
   now use `ScheduledScan`. `setup_core_schedules`/`sync_domain_monitoring_jobs`
   are no-ops. `django-q2` is removed from deps, `INSTALLED_APPS`, `Q_CLUSTER`,
   and logging; `qcluster` → `dbos_worker` in the Makefile.
   **Verified on Postgres:** app checks clean with no `django_q`; 5 pollers
   register; the user-schedule sweep fires due once+recurring, cleans/advances
   correctly, and leaves not-due schedules untouched; reports/WeasyPrint intact.
3. **Deployment — DONE (compose verified; CI still pending).** Option B
   topology (3 services): `docker-compose.yml` = `db` (postgres:17) + `web`
   (gunicorn, enqueue-only) + `worker` (`dbos_worker`, `NET_RAW`).
   `docker-entrypoint.sh` is role-aware (`OPENEASD_ROLE`): waits for Postgres;
   the web/init role migrates + collectstatic + admin-setup, the worker role
   waits for `migrate --check` then launches (no DDL race). Dockerfile CMD
   `qcluster`→`dbos_worker`. `k8s/`: new `postgres.yaml` (StatefulSet + headless
   Service + 10Gi PVC), `deployment.yaml` worker→`dbos_worker` and the SQLite
   `data` PVC/mounts removed, `configmap.yaml` gains `DB_*`/`DBOS_SCAN_CONCURRENCY`
   (DB_PASSWORD belongs in `openeasd-secret`), `pvc.yaml` drops the data PVC,
   `kustomization.yaml` includes `postgres.yaml`.
   **Verified:** `docker compose up` brings all 3 healthy; web migrates the app
   schema + DBOS creates its `dbos` schema in the same Postgres; the worker
   waits for migrations then launches and drains the `scans` queue; a scan
   enqueued from web is picked up and run by the worker.
   **Still pending:** CI (`.github/workflows/ci.yml`) needs a Postgres service
   container for the test job.
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
