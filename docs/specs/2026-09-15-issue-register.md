# Issue Register — Design Spec

> **Status:** ✅ Implemented — backfilled as the design contract for a subsystem
> built incrementally (the D-017 raw/enduring split, the register epic, and the
> triage-metadata fix #517). The shipped architecture is described in
> [`02-domain.md`](../02-domain.md) (Aggregate B) and CLAUDE.md; this spec is the
> per-feature design record the `04-technical` layer was missing for it. Where this
> doc and the running system disagree, the system is right and this file is
> corrected.

**Goal:** Turn a stream of disposable, per-scan `Finding` rows into a **persistent,
cross-scan `Issue` register** whose **triage survives re-observation** — so a
dismissed false positive stays dismissed, an assignee/rationale sticks, and "what
is still open on this domain, and for how long" is answerable across scans.

**Owner:** OpenEASD core. **Depends on:** the raw `Finding` layer + the
`_finalize_session` rollup seam. **Sibling of:**
[Asset-Centric Inventory](2026-09-06-asset-centric-inventory.md) (the same
raw→enduring rollup pattern, for assets). **Governing decision:**
[D-017](../DECISIONS.md#d-017--architecture-north-star-domain-centric-api-driven-ui-agnostic).

---

## 1. Motivation — triage must outlive the scan that found it

`Finding` is **raw provenance**: scoped to a `ScanSession`, bulky, and prunable
(D-016 / H3 retention). The same problem — "SPF record missing on example.com" —
produces a *fresh* `Finding` row every scan. If the human lifecycle lived there:

- **Triage would reset on every re-scan.** Dismissing a false positive, accepting a
  risk, or assigning an owner would silently revert the next time the tool ran.
- **There would be no cross-scan questions.** "First seen when? Still open? Open for
  how long? Resolved this month?" all require an identity that persists past one run.

Per D-017 the fix is **two layers, kept distinct**: the raw scan-scoped layer feeds a
**persistent, domain-centric fact layer** at finalize. `Issue` is that layer for
findings, exactly as `asset_inventory.Asset` is for raw attack surface. This is
Aggregate B of the domain model — the crown-jewel core domain.

---

## 2. Identity — title-independent, per-(rule, target), per-domain

An Issue is "the enduring thing a Finding is an occurrence of." Its cross-scan
sameness is a **value object**, `issue_key`, deliberately **not** derived from the
human title (titles get reworded; a reword must not orphan triage):

```
issue_key(check_id, target) = check_id \x1f target      # \x1f = unit separator
```

- **`check_id`** is the stable per-*rule* identity, independent of `title`:
  - *granular* tools (1 `check_type` : 1 rule — tls_checker, web_checker,
    ssh_checker, …) get `"{source}:{check_type}"` backfilled at finalize
    (`findings/checkid.py`, idempotent, only fills blanks);
  - *coarse* tools (domain_security, domain_probe) and the CVE/secret tools (nmap,
    nuclei, nuclei_network, js_secrets, github_secrets) set an explicit per-rule
    `check_id` at construction, so the backfill leaves them untouched.
- **`target`** scopes identity to a host: the same rule on a different host is a
  distinct Issue (per-asset triage). `\x1f` prevents a colon in `target` from
  colliding two keys.
- **Uniqueness** is `(domain, key)` — a DB `UniqueConstraint`. Issue therefore
  belongs to `Domain` (Aggregate B root), never to a scan.

**Register invariant (item 2):** a reworded title updates the Issue's *display*
metadata but keeps the same key → triage is preserved, no duplicate.

---

## 3. The model — `apps/core/data/issues/Issue`

Kept in table `findings_issue` (state-only split out of `findings/` — D-017; no data
migration). Fields, by role:

| Role | Fields |
|---|---|
| Identity | `domain` (FK, CASCADE), `key`, `check_id` |
| Display metadata (refreshed to latest occurrence) | `source`, `check_type`, `title`, `target`, `severity` |
| Lifecycle / triage (**the point of the layer**) | `status`, `assigned_to`, `resolution_note`, `resolved_at` |
| Cross-scan bookkeeping | `first_seen`, `last_seen`, `last_finding` (FK, SET_NULL), `asset` (FK, SET_NULL), `extra` |

`status` choices are shared with `Finding` (`open`/`acknowledged`/`in_progress`
→ active; `resolved`; `false_positive`/`accepted` → triaged). **Triaged** statuses
(`false_positive`, `accepted`) are excluded from the report register + the exposure
score (register items 6/7).

**Triage lives entirely here, not on `Finding`** (#517). `status` always did;
`assigned_to` + `resolution_note` were moved here so the *whole* triage record
survives re-scans. The per-scan `Finding` keeps its own `status` as provenance only.

---

## 4. Promotion — the rollup at finalize

`rollup_session_issues(session)` runs from `_finalize_session`, **after** the
`check_id` backfill and the asset rollup (so `Finding.asset` links exist), and is
**fail-graceful** (a rollup error never fails a scan). It is the *Promote* domain
event crossing from Aggregate A to B.

**Per finding** (excluding the `scan_coverage` meta-source): upsert one Issue per
`issue_key`:

- **New key** → create (`status="open"`, `first_seen=last_seen=now`).
- **Existing key** → refresh `last_seen`, `severity`, `last_finding`, `asset`, and
  `title` (display drift), and **carry triage forward untouched**. This is automatic:
  the update saves an explicit `update_fields` list that never includes the triage
  columns, so `status`/`assigned_to`/`resolution_note` persist for free.
- **Reappearance** → a `resolved` Issue seen again flips back to `open` and clears
  `resolved_at` (regression reopen).

**Auto-resolve unseen (item 4)** — only after a scan that *could* have seen
everything: a **completed** run of the **default full workflow** with **no tool
subset** (`session.subscan_tools is None` and `workflow.is_default`). Active-status
Issues not in `keys_seen` are set `resolved` (+ `resolved_at`); **triaged Issues are
left untouched** (a dismissal is a human decision, not a coverage fact). Partial
scans, category/subset subscans, and non-default workflows (e.g. Passive Scan) never
auto-resolve — their absence of an Issue doesn't prove it's gone.

**Idempotent (F1/H5):** every write is an upsert with no running counters, so a DBOS
step replay converges. **Subscans never roll up** (a subset can't define the Issue
set).

---

## 5. API & surfaces

- **`GET /api/issues/`** — ranked (severity via shared `SEVERITY_RANK`, then recency),
  filters `domain`/`status`/`severity`/`source`/`q`, paginated. **`GET
  /api/issues/summary/`** — totals by status + open-by-severity (actionable only).
- **`POST /api/issues/<id>/status/`** — the **canonical triage writer**: `status`
  (+ optional `assigned_to`, `resolution_note`; `None` = leave unchanged), with
  `resolved_at` stamped on resolve / cleared otherwise. (The `Finding` status
  endpoint remains for per-scan provenance; the enduring triage is here.)
- **PDF report — Issue Register section**: new-this-month / still-open-with-age /
  resolved-this-month, **excluding triaged** (items 6/7).
- **Frontend**: the finding/issue register views are the direction in
  [Finding-Centric UI](2026-09-12-finding-centric-ui-direction.md); built in the
  final frontend pass (backend-first).

---

## 6. What ships vs what's deferred

**Shipped (this contract):** the two-layer split, `issue_key`/`check_id` identity
(items 1–2), the finalize rollup with carry-forward + auto-resolve + reopen (items
3–4), triaged-exclusion from report + exposure score (items 6–7), the full triage
record on `Issue` (#517), and `/api/issues/` + report register.

**Deferred (open register items 5, 8, 9):** e.g. issue-level history/audit trail,
bulk triage, and SLA/age policies. **Next on this layer:** `verification_status`
(finding-verification spec) — it lands on `Issue` so "verified" persists across
scans, mirrored from the latest finding by this same rollup.

---

## 7. Design invariants (guarded by tests)

- Triage (status **and** assignee/note) survives a re-scan
  (`test_issue_register`, `test_issues_api`).
- A title reword keeps the same Issue (no re-key, no duplicate).
- Only a comprehensive full scan auto-resolves; partial/subset/non-default never do;
  triaged Issues are never auto-resolved.
- Rollup is idempotent on replay and fail-graceful (never fails a scan).
- Subscans do not roll up.
