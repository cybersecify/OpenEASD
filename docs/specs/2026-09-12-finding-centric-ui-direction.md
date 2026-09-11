# Finding-Centric UI, Grounded on Asset-Centric — Direction Spec

> **Status:** 🚧 In progress.
> - PR1 — restore the **Assets inventory UI** (list + detail), nav + routes (the
>   asset-centric grounding). *This PR.* The `/api/assets/` layer was never
>   removed, so this is UI wiring only.
> - PR2 — ✅ **persistent finding identity** (cross-scan `Issue` register +
>   finalize rollup). *The make-or-break prerequisite for finding-centric* — done:
>   status now persists across scans, dismissals stick.
> - PR3 — **Findings/Issues register UI** as the primary triage surface.
> - PR4 — dashboard cross-links + a "changes since last scan" feed.
>
> **This decision supersedes #406** ("make the UI strictly scan-centric"), which
> had removed the global Findings page and the Assets inventory pages. See
> *Relationship to #406* below.

## Goal

Make the console **finding-centric, grounded on an asset-centric surface**, with
scans as the supporting activity/history layer:

- **Assets** (the attack surface: subdomains / IPs / ports / URLs) are the
  durable, persistent spine — "what is exposed, since when, what changed."
- **Findings/Issues** (what's wrong, ranked, with a lifecycle) are the primary
  daily surface — "what do I fix / dismiss next."
- **Scans** become the *activity/history* substrate — how the data was produced,
  coverage/partial status, per-run deltas — not the organizing principle.

Rationale (why not scan-centric): OpenEASD is a **continuous** External Attack
Surface *Detection* platform (scheduled/monitoring scans, delta detection,
exposure-score trends). The objects a single operator reasons about persist
across scans — the surface and the issues on it. A scan is a point-in-time
collection run; organizing the UI around it forces scan-hopping to answer every
enduring question (as seen triaging the amnic.com false positives).

## Relationship to #406 (explicit reversal)

#406 deliberately went "strictly scan-centric": it removed the global Findings
page, the Assets inventory pages (list + detail), their nav/routes, and the
dashboard cards for them, and **moved finding triage into the Scan-Detail finding
modal** — with the note that "removing the global Findings page loses no
capability" because status stays editable there. The `/api/assets/` endpoints and
the `asset_inventory` data layer were **left intact**.

The gap that reversal left: **triage is scan-scoped and doesn't persist.**
`Finding` rows are per-`session` (`status` defaults `open` each run), so
dismissing a false positive in one scan's modal does not carry to the next scan —
the same false positives re-appear every run. For a product whose day-to-day is
*managing* recurring findings (exactly the amnic case), that is the wrong model.
This spec restores the cross-scan surfaces **and** adds the persistence that #406
never had (PR2), so the finding-centric view is durable, not re-noised each scan.

## The make-or-break prerequisite: persistent finding identity (PR2)

**Do not ship a finding-centric primary UI on per-scan findings.** Today a
"false positive" dismissal lives on a per-scan `Finding` row and is lost on the
next scan. Before the Findings register becomes the primary surface, findings
need a **cross-scan identity** so triage sticks.

**Chosen approach — a persistent `Issue` register, mirroring `asset_inventory`**
(which already solves the identical problem for assets, with a finalize rollup):

- New model keyed by `(domain, source, check_type, title[, asset])`, carrying
  `first_seen` / `last_seen` / `status` (`open`/`acknowledged`/`resolved`/
  `false_positive`) and a link to the latest `Finding` row.
- Rolled up at finalize (reuse the `rollup_session` pattern + fail-graceful hook).
- **`status` lives on the `Issue`, not the per-scan `Finding`.** Triage a false
  positive once → it stays dismissed across scans; if a `resolved` issue's
  finding reappears, the rollup re-opens it (regressed), while `false_positive`
  and `acknowledged` persist.
- Scope/group issues by `Finding.asset` — this is where "grounded on
  asset-centric" pays off: "the issues on *this* exposed host."

(A lighter interim — status carry-forward by key at finalize — is possible, but
the `Issue` model is the consistent choice and reuses a proven pattern + tests.)

## Coverage honesty (guardrail for PR3)

A findings-first landing must never let an empty/short list read as "clean" when
it is really low coverage or a partial scan — the same "never fake-clean"
principle behind the coverage-regression finding and the F4 fix. The Findings
register and dashboard must surface a **coverage / partial-scan banner**
(endpoints probed vs blocked, WAF vendor, last-scan status) alongside the counts.

## Phased delivery

| PR | Scope | Risk |
|----|-------|------|
| **PR1** *(this)* | Restore Assets list + detail UI, nav + routes | Low — API intact, restores #339 code |
| **PR2** | `Issue` model + finalize rollup + cross-scan status; tests | Medium — new model + migration |
| **PR3** | Findings/Issues register UI (primary), ranked (severity + EPSS/KEV + AI triage), triage actions that persist; coverage banner | Medium |
| **PR4** | Dashboard: asset KPI + issue summary + Finding→asset cross-links; "changes since last scan" feed | Low |

Scans stay first-class as **Activity/History** throughout — starting/monitoring
scans, live progress, coverage/partial signals, and per-run deltas remain
scan-level and are not removed.

## Non-goals

- No multi-user/RBAC (single-admin by design).
- Not removing scans or the scan-detail view — only demoting scans from *the*
  organizing principle to the activity layer.
- PR1 does not yet change the dashboard or add the Findings register; it only
  restores the asset surface as the grounding for PR3.
