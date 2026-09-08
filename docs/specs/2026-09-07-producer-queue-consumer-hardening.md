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
- Instrument at the points that already record timings: `workflows/runner.py`
  (`_run_single_step`) for per-tool metrics, `scans/pipeline.py` (`_finalize_session`)
  for scan-level metrics + final status.
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

## 6. Non-goals / explicitly out of scope

- **Do NOT make the pattern "textbook pure."** The multi-producer (API +
  scheduler + AI), the consumer feedback loop (AI agent re-enqueue), and the
  producer result-polling are **features**, not deviations to remove.
- No new message broker (Redis/RabbitMQ) — Postgres/DBOS is the durable queue.
- No architecture change; no engine extraction (see DECISIONS.md / the
  keep-Django-monolith decision).

## 7. Sequencing (each independently shippable)

1. **H1 — alert idempotency** (½ PR, no migration) — closes the one *correctness*
   gap; highest leverage, lowest cost. Do first.
2. **H3 — retention** (1 PR, opt-in) — prevents slow-motion DB growth.
3. **H2 — `/metrics`** (1 PR) — highest operational value; needs the multiprocess
   decision above, so worth reviewing this section before coding.

## 8. Verification

- H1: dispatch alerts twice → second is a no-op; alert-history unchanged.
- H2: run a scan → counters move; `/metrics` scrapeable on web AND worker.
- H3 (enabled): after N+1 scans of a domain, only N retained; latest always kept;
  disabled → nothing deleted.
- Whole: with all three merged and features unused/disabled, a scan is
  byte-identical to today (additive-safety check).
