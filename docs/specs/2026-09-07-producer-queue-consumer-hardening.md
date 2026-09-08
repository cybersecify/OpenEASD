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
5. **H4 — watchdog ↔ DBOS-resume reconcile** (1 PR) — closes the recovery-path
   overlap. Lowest priority (narrow race, high timeout); do last.

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
- Whole: with every feature unused/disabled, a scan is byte-identical to today
  (additive-safety check).
