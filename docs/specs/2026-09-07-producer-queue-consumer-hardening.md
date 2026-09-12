# Producer → Queue → Consumer Hardening — Plan

> **Status:** Draft for review. Execution belongs to a dedicated session, not the
> session that authored this. This document is the plan; each phase is an
> independently-shippable PR.

**Goal:** OpenEASD's core *is* a durable Producer → Queue → Consumer system (web
enqueues → Postgres/DBOS queue → worker executes). The pattern is the right one
and is ~90% cleanly implemented. This plan closes the three *open cons* of that
pattern — **at-least-once side-effects, low observability, and an unbounded
result store** — to make it correct, observable, and bounded. It does **not**
change the architecture or remove features.

A later **resilience track (H8–H10)** extends the plan with fixes for a
*demonstrated* failure mode — the 2026-09-12 preprod queue-jam, where a worker
rollout during active scans stranded in-flight workflows on the old app-version
and permanently saturated the `concurrency=2` queue. These are deploy-safety and
state-consistency hardening, same additive-and-safe discipline.

**Owner:** OpenEASD core. **Depends on:** nothing external.

---

## 1. Motivation — the pattern is correct; three cons are still live

The Producer → Queue → Consumer pattern's benefits (decoupling, durability,
responsiveness, independent scaling) all map to OpenEASD's needs and are
delivered. But three standard cons of the pattern remain un-mitigated:

| Con of the pattern | Symptom in OpenEASD |
|---|---|
| **At-least-once execution** — a replayed job re-runs its side-effects | `_finalize` (one DBOS step) also dispatches alerts; a crash after Slack-send but before the step checkpoints re-sends alerts on resume → **duplicate alerts** |
| **Hard to trace across the process boundary** | No `/metrics`; "is the worker healthy? queue backing up? which tool is slow?" is invisible — only `/health/` exists |
| **Unbounded result store** | Nothing prunes old `ScanSession`/`Finding`/asset rows; a monitored deployment grows the DB without limit |

These are not architecture flaws — they are the price of the pattern, payable
with three contained changes.

## 2. Design principles

1. **Additive and safe.** Each phase leaves current behaviour unchanged when its
   feature is unused/disabled. No feature is removed to make the pattern "purer"
   (multi-producer, the AI-agent feedback loop, and status-polling all stay).
2. **DBOS-native.** New periodic work is a DBOS `@scheduled` workflow (like the
   existing token-purge / watchdog), not a new scheduler.
3. **Single-user.** No per-user concerns (see `docs/DECISIONS.md`).
4. **Opt-in where destructive.** Retention (which deletes data) defaults OFF.

## 3. Phase H1 — Consumer idempotency (exactly-once side-effects) — ✅ SHIPPED

> **Status:** ✅ Implemented — `_dispatch_alerts` guards on
> `session.alerts.filter(status="sent").exists()`; tests in
> `test_notifications.py::TestAlertIdempotency` (skip-when-sent, dispatch-when-none,
> retry-when-only-failed). No migration.

**Problem:** `_dispatch_alerts` (in the finalize step) can fire twice if the step
is replayed after a partial crash → duplicate Slack/Teams alerts.

**Change** (smallest — no migration; reuse the existing `Alert` table as the key):
- In `apps/core/scans/pipeline.py::_dispatch_alerts`, guard at the top:
  `if session.alerts.filter(status="sent").exists(): return` — a session whose
  alerts already went out is not re-alerted on a replay.
- Optionally extend the same guard to any other replay-sensitive side-effect in
  finalize (AI post-scan is already idempotent/gated; verify).

**Tests:** a second `_dispatch_alerts(session)` after a successful first sends
nothing; a first call with no prior `Alert` rows still sends.

**Effort:** ~½ PR. No schema change.

## 4. Phase H2 — Queue / consumer observability (`/metrics`)

> **Status:** ✅ Shipped — as a **DB-backed exporter** (deliberate deviation from the
> in-process-counter design below). `apps/core/console/observability/metrics.py`
> `render_metrics()` queries Postgres on each scrape and emits Prometheus text;
> `GET /metrics` (web tier, unauthenticated like `/health`, `METRICS_ENABLED`
> toggle, `no-store`). Metrics: `openeasd_scans{status}`,
> `openeasd_scan_queue_depth`, `openeasd_findings{severity}`, `openeasd_domains`,
> `openeasd_scan_last_journey_seconds` (enqueue=start_time → finalize=end_time,
> principle #13), and `openeasd_seconds_since_last_progress` (worker liveness).
> A `ScanSession.last_progress_at` **heartbeat** (migration `0015`) is stamped by
> `_run_single_step` on every step completion — it powers both the liveness metric
> and **H10**. **Why DB-backed, not in-process counters:** it needs no worker HTTP
> listener and no cross-pod aggregation (the web↔worker problem the options below
> wrestle with), is drift-free (reflects real stored state), and survives restarts.
> Trade-off: point-in-time gauges + stored-timestamp journey latency, no per-request
> histograms — sufficient at this scale. No new dependency. Tests:
> `tests/unit/test_metrics.py` (9).

**Problem:** long-running durable work with no runtime visibility.

**Change:**
- Add `prometheus-client`.
- New `apps/core/observability/` (metrics module): Counters/Histograms —
  `openeasd_scans_total{status}`, `openeasd_scan_duration_seconds`,
  `openeasd_tool_runs_total{tool,status}`, `openeasd_tool_duration_seconds{tool}`,
  `openeasd_findings_total{severity}`, `openeasd_scan_queue_depth` (gauge).
- **Measure the whole journey, not just each run** (pipeline principle #13):
  add `openeasd_scan_journey_seconds` = time from the *trigger* (enqueue) to the
  *final delivered output* (finalize complete, or alert dispatched) — not just
  per-phase durations. "The run succeeded" ≠ "the alert went out"; log the
  end-to-end latency so a slow queue or a stuck alert path is visible.
- Instrument at the points that already record timings: `workflows/runner.py`
  (`_run_single_step`) for per-tool metrics, `scans/pipeline.py` (`_finalize_session`)
  for scan-level metrics + final status; capture the enqueue timestamp (on the
  `ScanSession`) so journey time = finalize_time − enqueue_time.
- Expose `GET /metrics` (Prometheus text format) — unauthenticated like `/health/`,
  or `?token=`-gated.
- **Deeper `/health/`** (optional): add a DB-connectivity check to the JSON body.

**The one design decision (must be chosen here):** metrics are **in-process**, and
producer counters increment in the **worker** process while `/metrics` would be
served by the **web** process — different pods. Options:
  - **(A)** Expose `/metrics` on **both** web and worker (worker adds a tiny HTTP
    listener); scrape both. Simplest correct approach — **recommended.**
  - **(B)** `prometheus_client` multiprocess mode with a shared dir (only works
    within one pod's processes — doesn't span web/worker pods).
  - **(C)** Push to a Pushgateway from the worker. More moving parts.
Recommend **(A)**: web exposes console/request metrics, worker exposes
scan/tool/queue metrics; the scraper collects both. Document the split.

**Tests:** metric increments on a scan; `/metrics` returns valid Prometheus text;
auth behaviour.

**Effort:** ~1 PR (the instrumentation points already exist).

## 5. Phase H3 — Bounded result store (retention / pruning)

> **Status:** ✅ Shipped — `prune_old_scans()` (`scheduler.py`) + `scheduled_scan_prune`
> (`@DBOS.scheduled`, `SCAN_PRUNE_CRON` default `30 3 * * *`). OFF by default
> (`SCAN_RETENTION_ENABLED`); when on, keeps per domain the newest
> `SCAN_RETENTION_KEEP_PER_DOMAIN` (30) scans + any within
> `SCAN_RETENTION_MAX_AGE_DAYS` (180), always keeps the single newest, never deletes
> pending/running, and cascades to assets/findings. Hygiene cron (self-gates on the
> setting), so NOT tied to `SCHEDULED_SCANS_ENABLED`. Tests:
> `tests/unit/test_scan_retention.py` (7). No migration.

**Problem:** unbounded growth of scan history.

**Change:**
- Settings: `SCAN_RETENTION_ENABLED` (**default False**),
  `SCAN_RETENTION_KEEP_PER_DOMAIN` (e.g. 30), `SCAN_RETENTION_MAX_AGE_DAYS` (e.g. 180).
- `apps/core/scheduler/scheduler.py::prune_old_scans()` — per domain, keep the
  newest N completed `ScanSession`s (and any within max-age), delete older ones
  (cascade wipes their assets/findings). **Never** delete the latest per domain;
  the `asset_inventory` first/last-seen preserves the long-term surface history,
  so pruning raw scans doesn't lose the "surface over time" story.
- `apps/core/durable/workflows.py`: `@DBOS.scheduled @DBOS.workflow
  scheduled_scan_prune()` calling it — exact copy of the `scheduled_token_purge`
  pattern.

**Tests:** keeps-N, respects max-age, never deletes the latest, cascade correct,
no-op when disabled.

**Effort:** ~1 PR. Slots into the existing `@scheduled` + scheduler-callable pattern.

## 5b. Phase H4 — reconcile the watchdog with DBOS resume (design smell)

**Problem:** `reap_stuck_scans` (the `scheduled_watchdog` cron) and DBOS's own
crash-resume are **two uncoordinated recovery mechanisms** for the same scans.
The watchdog reaps a `running` scan by `start_time` age → marks it `failed`/
`partial` and fails its in-flight `WorkflowStepResult`s. But on worker restart
DBOS **resumes** a crashed scan from its last checkpoint. In a narrow window — a
scan that legitimately ran a long time, crashed, and whose worker was down past
`SCAN_TIMEOUT_MINUTES` — the watchdog can reap a scan **while DBOS is resuming
it**: conflicting `ScanSession.status`, spurious `failed` step rows, and status
churn (DBOS usually wins if its resumed run finishes and calls `_finalize`).

**Context:** low-probability today — `SCAN_TIMEOUT_MINUTES` is set very high
(~24h) precisely so a healthy long run is never flipped mid-scan. The watchdog is
a **Django-Q-era backstop** whose role narrowed once DBOS added real resume; it's
now mostly needed for **orphaned `pending`** scans (enqueued but never picked up),
not for reaping `running` ones (DBOS handles those).

**Change (options, smallest first):**
- **(A)** Gate the watchdog to **skip `running` sessions that still have a live
  DBOS workflow** (query the `dbos` workflow-status for the session's handle;
  only reap `running` scans with no active/enqueued DBOS workflow). Keep the
  `pending`-reap path unchanged (that's the part still genuinely needed).
- **(B)** Reframe the watchdog as a **pure DBOS-orphan reaper** — reap only
  sessions whose DBOS workflow is terminal/absent but whose `ScanSession` is
  still `running`/`pending`.
Recommend **(A)** — smallest change, preserves the pending-orphan safety net.

**Tests:** a `running` session with a live DBOS workflow is NOT reaped; a
`pending` orphan past its cutoff still is; a `running` session with a
terminal/absent DBOS workflow past cutoff is reaped as today.

**Effort:** ~1 PR. **Priority:** low (narrow race, high timeout) — do after H2/H3.

## 5c. Phase H5 — idempotent phase-group steps (pipeline principle #4)

> **Status:** ✅ Shipped — implemented at **per-tool** granularity (finer than the
> per-group option A), in `runner.py::_run_single_step`. The existing F1b resume
> guard already skips tools that reached a terminal state and re-runs only a tool
> left non-terminal by a crash; in exactly that re-run branch we now
> **delete the tool's prior `Finding` rows for the session** (`source == tool`)
> before re-executing, so Finding writes (bulk_create, no unique constraint)
> converge instead of duplicating. Assets need no cleanup — they are
> `(session, …)`-unique and written with `ignore_conflicts=True`, so re-writes are
> already idempotent. Tests: `test_workflow_runner.py::TestResumeIdempotencyH5`
> (3: crash-resume no-dup, completed-tool-not-rerun, first-run-normal). No migration.

**Problem:** `_run_phase_group` is a `@DBOS.step` that runs *all* tools in a phase.
DBOS skips a step that **completed**, but a step that **crashes mid-run** re-runs
the whole group on resume — so a tool that already wrote its rows before the crash
writes them **again** → duplicate `Finding`/asset rows. The pipeline principle is
*"make every workflow idempotent: re-running with the same input leaves the DB in
the same state — delete-then-insert or update-or-create, never append."* Today the
tool save paths mostly **append**, so a replayed phase group is not idempotent.

**Change (options):**
- **(A) Per-session delete-then-insert at the phase-group boundary** — before a
  phase group runs (or on its retry), clear that group's prior rows for the session
  (by `source`), so a re-run converges to the same state. Cleanest, matches the
  principle directly.
- **(B) Per-tool upsert** — give each tool's save path an `update_or_create` keyed
  by `(session, source, check_type, target[, port/url])` so re-writes dedupe.
  More work spread across tools, but no destructive delete.
- **(C) Finer step granularity** — one `@DBOS.step` per *tool* instead of per
  *phase group*, so a crash only re-runs the one tool (still needs A or B for that
  tool's own partial write).
Recommend **(A)** as the smallest correctness fix; **(C)** is a larger change that
also improves retry granularity (relates to principle #3).

**Tests:** run a phase group, simulate a mid-group crash + resume, assert no
duplicate findings/assets; a clean re-run of a completed scan is a no-op.

**Effort:** ~1 PR (A). **Priority:** medium — it's the one *correctness* gap in the
"durable" claim after H1 (alerts). Do after H2/H3, before or with H4.

## 5d. Phase H6 — `@durable_task` engine adapter (pipeline principle #11) — ✅ SHIPPED (slice 1)

> **Status:** ✅ Slice 1 shipped — `apps/core/engine/durable/task.py` (`@durable_task`
> with in-process `task()`, `task.delay()`, `dedupe` template). The two **one-step**
> tasks `ai_triage` + `agent_step` are converted; `enqueue_ai_triage`/`enqueue_agent_step`
> now delegate to `.delay()`. `run_scan` stays an explicit **multi-step** workflow
> (per-phase checkpointing) — by design, not converted. The `@scheduled` hygiene crons
> are left for **H7** (they fit the `ScheduledJob` model better than a one-step task).
> Verified: `configure_dbos()` builds the engine and registers the adapter workflows;
> 7 adapter tests + 97 enqueue/integration tests green. Tests:
> `tests/unit/test_durable_task.py`.

**Problem:** workflow bodies use `@DBOS.workflow`/`@DBOS.step` **directly**, so the
engine leaks into every task: tasks can't run without a DBOS engine (harder to
test), and the enqueue surface is ad-hoc (`enqueue_scan`/`enqueue_ai_triage`/
`enqueue_agent_step` each hand-roll `EnqueueOptions`). Principle #11: *"keep the
engine behind an adapter — one module knows the workflow library; every task uses
a thin decorator."*

**Reference (proven next door):** the sibling `cybersecify/backend` repo ships
exactly this — `apps/core/durable/task.py`'s `@durable_task("name")`, a
Celery-shaped surface over DBOS:
```
task(*args)                    run the body now, in-process (NO DBOS — tests need no engine)
task.delay(*args, **kw)        durably enqueue on the task's queue
task.apply_async(queue=, countdown=, dedupe=)
task.request.retries           attempt counter
```
Under the hood it registers the DBOS workflow(s); no body imports `dbos`.

**Change:** add `apps/core/engine/durable/task.py` with a `@durable_task` decorator;
migrate `run_scan`/`ai_triage`/`agent_step` + the `@scheduled` hygiene jobs onto it;
collapse the three `enqueue_*` helpers into `task.delay()/apply_async()`. Keep the
`deduplication_id` behaviour (H1/#5) inside the adapter.

**Tests:** a task body runs in-process with no DBOS engine; `.delay()` enqueues;
dedup still holds; existing scan/agent flows unchanged.

**Effort:** ~1–2 PRs. **Priority:** medium — big testability + isolation win, but
touches the durable core, so do it deliberately (not under time pressure).

## 5e. Phase H7 — `ScheduledJob` table for system crons (pipeline principle #8)

**Problem:** the system crons (daily scan, monitoring/user sweeps, watchdog, token
purge) are `@DBOS.scheduled` decorators with cron strings from `settings` — changing
a schedule needs a deploy or env change. Principle #8: *"put every timed job in one
editable table; rows in an admin table change without a deploy."* (OpenEASD already
has a partial version — `ScheduledScan` for user scans — but not for the system jobs.)

**Reference:** `cybersecify/backend`'s `ScheduledJob` model
(`name, task, cron, timezone, queue, kwargs, enabled, description`) — the DBOS
scheduler reads rows; operators edit them in Django admin.

**Change:** add a `ScheduledJob` table (extend/rename the existing `ScheduledScan`
concept, or a new model); a single DBOS `@scheduled` sweep reads due enabled rows
and dispatches their `task` via the H6 `@durable_task` registry. Seed the current
system crons as rows on migrate. Gate by `SCHEDULED_SCANS_ENABLED` as today.

**Tests:** a disabled row never fires; an edited cron takes effect without a deploy;
the seeded system jobs match today's cadence; `SCHEDULED_SCANS_ENABLED=false` still
suppresses scans.

**Effort:** ~1 PR (cleanest **after** H6, so scheduled rows dispatch through the
adapter). **Priority:** medium — operator-experience win.

## 5f. Phase H8 — drain / quiesce the queue before a worker rollout (deploy safety)

> **Status:** ✅ Slice 1 shipped — the **safe, race-free** core. A
> `reap_orphaned_scan_workflows()` reaper (`scheduler.py`) cancels ENQUEUED/PENDING
> `run_scan` workflows whose `ScanSession` is terminal/missing (phantoms holding a
> `scans`-queue slot); it runs automatically in the `scheduled_watchdog` cron
> (after `reap_stuck_scans` flips stale sessions terminal) and on demand via
> `manage.py reap_orphan_scans [--dry-run]`. Drain runbook added to
> `docs/DEVELOPMENT.md` (`SCHEDULED_SCANS_ENABLED=false` + wait + post-rollout
> reap). Tests: `tests/unit/test_orphan_reaper.py` (9). **Deferred:** the
> *auto version-orphan reaper on worker startup* (option 2a) — it has a
> rolling-deploy race (a still-live old-version worker's in-flight scans) and
> needs `DBOS__APPVERSION` pinning we don't have; the terminal-session reaper
> subsumes its practical need (a pending version-orphan is reaped to terminal by
> `reap_stuck_scans` after `SCAN_PENDING_TIMEOUT_MINUTES`, then cancelled here).
> The *running*-session version-orphan (held up to the 24h cap) is **H10's** gap.

> **Origin:** a real 2026-09-12 preprod incident. The v2.16.0 rollout landed
> **while scans were running**. DBOS pins an in-flight workflow to the code's
> **app-version hash**; the new worker computed a different hash, so it could
> **not recover** the two `PENDING` `run_scan` workflows left mid-flight by the
> replaced worker. Because the `scans` queue is `concurrency=2`, those two
> un-recoverable `PENDING` rows **occupied both slots permanently** → every scan
> enqueued afterward (3 of them) sat `pending` indefinitely. Recovery required
> manually cancelling the orphans via `DBOSClient.cancel_workflow`. Memory:
> `project_dbos_rollout_queue_jam.md`.

**Problem:** a worker rollout (k8s `apply -k` / `rollout restart`, or any image
bump) during active scans strands the in-flight workflows on the **old**
app-version. With a small `concurrency` (2), a handful of stranded `PENDING`
workflows is enough to **saturate the queue forever** — a self-inflicted full
stall with no automatic recovery. This is distinct from a clean crash (where the
*same-version* worker resumes): the version **changes** across a deploy, which is
precisely when resume does not apply.

**Change (options, combine 1 + one of a/b):**
1. **Document + script a pre-rollout drain** (smallest, do first): a
   `just drain-scans` / runbook step that refuses (or waits) to roll the worker
   while `ScanSession.objects.filter(status__in=["running","pending"])` is
   non-empty — or scales the worker to 0, lets in-flight scans finish, then rolls.
   Pair with the existing `SCHEDULED_SCANS_ENABLED=false` to stop *new* enqueues
   during a maintenance window.
2. Pick one automatic backstop so a drain that was skipped still recovers:
   - **(a)** A startup **version-orphan reaper** in the worker entrypoint / a DBOS
     `@scheduled` sweep: on launch, find `run_scan` workflows in `ENQUEUED`/`PENDING`
     whose `application_version` ≠ the current worker's, and **cancel** them (their
     `ScanSession` is re-enqueued fresh under the new version if still wanted).
     This is the programmatic form of the manual fix from the incident.
   - **(b)** Raise/curb reliance on a fixed `concurrency` so a couple of stranded
     rows can't wholesale-block — e.g. a dedicated higher-concurrency lane for
     quick passive scans (relates to the route-by-resource idea deliberately not
     adopted for the general case; here it's a safety valve, not choreography).
Recommend **1 + 2(a)**: a drain runbook to *prevent* it, plus a version-orphan
reaper to *auto-heal* it. (a) must use the DBOS client API
(`cancel_workflow`) — never a raw `UPDATE dbos.workflow_status` (the latter
corrupts queue accounting and is blocked by tooling safety classifiers anyway).

**Tests:** simulate a stranded `PENDING` with a mismatched `application_version`
→ the reaper cancels it and frees the slot; a same-version `PENDING` (legit
resume) is **never** touched; drain refuses to roll while scans are in-flight.

**Effort:** ~1 PR (drain runbook + reaper). **Priority:** **high** — this failure
has *already occurred* and fully stalls the scan subsystem with no auto-recovery.

## 5g. Phase H9 — reconcile phantom `PENDING` workflows with terminal sessions

> **Origin:** same 2026-09-12 incident. Observed `scan-25` (raga.ai) with
> `ScanSession.status = "failed"` **but** its DBOS workflow still `PENDING`,
> `executor=local` — a "phantom" holding a `concurrency` slot with no live
> session behind it. The two sources of truth (Django `ScanSession` and
> `dbos.workflow_status`) had **diverged**, and nothing reconciles them.

**Problem:** `ScanSession.status` (domain truth) and the DBOS workflow status
(engine truth) are separate records that can drift — a session reaped to
`failed`/`cancelled` while its DBOS workflow lingers `PENDING`/`ENQUEUED`. A
phantom `PENDING` silently consumes a scarce `concurrency` slot indefinitely, and
nothing detects or clears it. This is the **inverse** of H4 (which stops the
watchdog reaping a *live* scan): H9 cleans up an *orphaned engine workflow whose
session is already terminal*.

**Change:** add a lightweight **reconciliation sweep** (DBOS `@scheduled`, or fold
into the H4/watchdog pass): for each non-terminal `run_scan` DBOS workflow
(`ENQUEUED`/`PENDING`), look up its `ScanSession` (via the `deduplication_id`
`scan-{id}` ↔ session id mapping observed in the incident); if the session is
**terminal** (`completed`/`failed`/`partial`/`cancelled`), **cancel the workflow**
(`cancel_workflow`) to free the slot. Emit a log/metric so a recurring divergence
is visible (it signals a bug upstream, e.g. the watchdog reaping without
cancelling the workflow — which H4 should also fix at the source).

**Relationship to H4:** H4 makes the watchdog *not* reap sessions with a live DBOS
workflow; H9 makes a separate pass *clean up* DBOS workflows whose session is
already dead. Ideally H4 also **cancels the DBOS workflow when it reaps a session**
(fixing the divergence at the source), leaving H9 as the periodic safety net.
Do H9 **with or right after H4**.

**Tests:** a `PENDING` workflow whose session is `failed` → reconciler cancels it
and frees the slot; a `PENDING` workflow with a `running` session (legit
in-flight) is untouched; reconciler is idempotent (re-running cancels nothing new).

**Effort:** ~1 PR (shares the session↔workflow lookup with H4/H8). **Priority:**
**medium-high** — a single undetected phantom halves a `concurrency=2` queue.

## 5h. Phase H10 — short "no-progress" liveness watchdog (distinct from the 24h cap)

> **Origin:** same incident exposed the gap. `SCAN_TASK_TIMEOUT` / the watchdog
> cutoff is ~**24h** (deliberately high so a healthy long scan is never flipped
> mid-run, per H4). But that means a **genuinely wedged** scan — or a phantom
> holding a slot — can sit for **up to a day** before anything reaps it. On a
> `concurrency=2` queue, two wedged slots = a **24h total stall**.

**Problem:** there is exactly one timeout (the 24h hard cap), serving two
conflicting goals: (i) *don't kill healthy long scans* (wants a **high** cutoff)
and (ii) *free a wedged slot quickly* (wants a **low** cutoff). A single value
can't do both, so today it's tuned for (i) and (ii) is unprotected.

**Change:** add a **liveness / no-progress** signal separate from total runtime.
- Have the runner stamp a **heartbeat** on the `ScanSession` (e.g.
  `last_progress_at`) whenever it completes a phase-group step or writes a batch of
  rows (the instrumentation point H2 already adds).
- A **short** watchdog (`SCAN_NO_PROGRESS_MINUTES`, e.g. 30–60m, ≪ the 24h cap)
  reaps a `running` scan whose `last_progress_at` is stale **and** whose DBOS
  workflow is not actively advancing (compose with H4's live-workflow check and
  H9's reconcile) — freeing the slot in minutes, not a day, **without** killing a
  scan that is slow-but-progressing (its heartbeat keeps moving).
- Keep the 24h hard cap as the absolute ceiling for a scan that *is* progressing
  but has simply run too long.

**Tests:** a scan emitting heartbeats past `SCAN_NO_PROGRESS_MINUTES` is **not**
reaped (slow-but-alive); a scan with a stale heartbeat past the cutoff **is**
reaped and its slot freed; the 24h cap still applies to a heartbeating-but-
overlong scan.

**Effort:** ~1 PR (the heartbeat stamp rides on H2's instrumentation; the watchdog
extends the existing reaper). **Priority:** **medium-high** — directly bounds the
blast radius of H8/H9 failures on the small-concurrency queue. Implements pipeline
principle #12 (per-stage safety net) at a useful granularity.

## 6. Non-goals / explicitly out of scope

- **Do NOT make the pattern "textbook pure."** The multi-producer (API +
  scheduler + AI), the consumer feedback loop (AI agent re-enqueue), and the
  producer result-polling are **features**, not deviations to remove.
- No new message broker (Redis/RabbitMQ) — Postgres/DBOS is the durable queue.
- No architecture change; no engine extraction (see DECISIONS.md / the
  keep-Django-monolith decision).

## 7. Sequencing (each independently shippable)

1. **H1 — alert idempotency** (½ PR, no migration) — closes the *alert* correctness
   gap; highest leverage, lowest cost. **✅ Shipped (#355).**
2. **H5 — idempotent phase-group steps** (1 PR) — the remaining *correctness* gap
   in the "durable" claim (principle #4); a replayed phase must not double-write.
3. **H3 — retention** (1 PR, opt-in) — prevents slow-motion DB growth.
4. **H2 — `/metrics` + journey timing** (1 PR) — highest operational value
   (principle #13); needs the multiprocess decision above, so review that section
   before coding.
5. **H6 — `@durable_task` engine adapter** (1–2 PRs) — engine isolation +
   testability (principle #11); do deliberately, it touches the durable core.
6. **H7 — `ScheduledJob` table** (1 PR, after H6) — editable system crons
   (principle #8); operator-experience win.
7. **H4 — watchdog ↔ DBOS-resume reconcile** (1 PR) — closes the recovery-path
   overlap. Lowest priority (narrow race, high timeout); do last.

**Resilience track (H8–H10) — surfaced by the 2026-09-12 preprod queue-jam
incident, not the original audit.** These address a *demonstrated* full-stall
failure mode, so they jump ahead of the lower-priority cleanup items:

8. **H8 — drain/quiesce before worker rollout + version-orphan reaper** (1 PR) —
   **highest resilience priority**; the failure has already happened and fully
   stalls scans with no auto-recovery. Do alongside or before H2.
9. **H9 — reconcile phantom `PENDING` workflows with terminal sessions** (1 PR) —
   do **with or right after H4** (shares the session↔workflow lookup; ideally H4
   cancels the workflow at reap time and H9 is the periodic safety net).
10. **H10 — short no-progress liveness watchdog** (1 PR) — bounds the blast radius
    of H8/H9 on the `concurrency=2` queue; rides on H2's heartbeat instrumentation,
    so sequence it **after/with H2**, composing with H4 + H9.

**Reference implementation:** H2 (metrics), H6 (`@durable_task`), and H7
(`ScheduledJob`) are all **proven in the sibling `cybersecify/backend` repo**
(`config/metrics.py`, `apps/core/durable/task.py`, `ScheduledJob` model) — copy the
shape, swap the chess domain for scans. H5's delete-then-insert idempotency and
H3's workflow-history cleanup also mirror that repo. It's the same team's
choreographed variant of this stack; use it as the working reference.

**Framework alignment:** H5 and H2's journey-timing addition come from an audit
against a 14-point pipeline-design checklist — H5 = principle #4 (idempotent,
delete-then-insert not append), H2 = principle #13 (measure the whole journey,
not each run). H4 = principle #12 (per-stage safety net + alarm). The checklist's
#3/#6/#9 (many small workflows, write-triggered stages, per-resource queues) are a
*choreography* pattern OpenEASD deliberately does not adopt — it is an
*orchestrated* single-workflow-per-scan pipeline (valid for a fixed dataflow); see
DESIGN.md "Workflow vs. Pipeline". Those are not tracked as gaps.

## 8. Verification

- H1: dispatch alerts twice → second is a no-op; alert-history unchanged.
- H5: crash a phase group mid-run + resume → no duplicate findings/assets; a
  re-run of a completed scan is a no-op (idempotent, principle #4).
- H3 (enabled): after N+1 scans of a domain, only N retained; latest always kept;
  disabled → nothing deleted.
- H2: run a scan → counters move; `/metrics` scrapeable on web AND worker;
  `openeasd_scan_journey_seconds` reflects enqueue→final-output latency (#13).
- H4: a `running` session with a live DBOS workflow is not reaped; a `pending`
  orphan past cutoff still is.
- H6: a `@durable_task` body runs in-process with no DBOS engine; `.delay()`
  enqueues; dedup preserved; scan/agent flows unchanged.
- H7: a disabled `ScheduledJob` row never fires; an edited cron takes effect with
  no deploy; `SCHEDULED_SCANS_ENABLED=false` still suppresses scans.
- H8: a stranded `PENDING` `run_scan` with a mismatched `application_version` is
  cancelled by the version-orphan reaper and its slot freed; a same-version
  `PENDING` (legit resume) is never touched; drain refuses to roll the worker
  while scans are in-flight.
- H9: a `PENDING` workflow whose `ScanSession` is terminal (`failed`/`cancelled`)
  is cancelled and its slot freed; a `PENDING` with a `running` session is
  untouched; the reconciler is idempotent.
- H10: a scan emitting heartbeats past `SCAN_NO_PROGRESS_MINUTES` is NOT reaped
  (slow-but-alive); a scan with a stale heartbeat past the cutoff IS reaped and
  its slot freed; the 24h hard cap still applies to a heartbeating-but-overlong run.
- Whole: with every feature unused/disabled, a scan is byte-identical to today
  (additive-safety check).
