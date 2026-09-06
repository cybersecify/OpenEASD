# Asset-Centric Inventory — Design Spec

> **Status:** Draft for review. Execution belongs to a dedicated session, not the
> session that authored this. This document is the design contract; an
> implementation plan (`writing-plans`) should be derived from it before coding.

**Goal:** Give OpenEASD a persistent, deduplicated **asset inventory** — every
subdomain / IP / port / URL a domain has ever exposed, with `first_seen` /
`last_seen` / `status` and per-asset finding history — and an asset-first UI to
pivot around it. Turn "here are this scan's results" into "here is my attack
surface over time, and what's wrong with each piece of it."

**Owner:** OpenEASD core. **Depends on:** nothing external. **Blocks:** an
asset-centric UX (an inventory page, asset detail, asset→findings pivot).

---

## 1. Motivation — the model is asset-structured, the UX is not

The data model already discovers assets in a hierarchy
(`Subdomain → IPAddress → Port → URL`), but those rows are **scoped to a
`ScanSession`**: the same `api.example.com` observed across five scans is five
disconnected rows. There is:

- **No persistent asset identity** — you cannot ask "when did this host first
  appear? is it still live? what has been found on it across scans?"
- **No asset inventory surface** — the UI navigation is `Domains · Scans ·
  Findings · Insights`; discovered assets appear only *inside* a single scan's
  detail view. There is no "all my subdomains/IPs/ports, click one to pivot."

The result is a **scan-/finding-centric** product. For attack-surface
management, the asset is the durable unit of interest — findings come and go, but
"do I still have this forgotten host exposed?" is the question that persists.

## 2. Design principles (these constrain every decision below)

1. **Additive and reversible.** With the inventory empty/off, the current
   scan- and finding-centric UX must be byte-for-byte unchanged. No existing
   endpoint, page, or test changes behavior.
2. **Tools stay untouched.** Scanner apps keep writing session-scoped assets
   exactly as today. The inventory is a rollup layer, not a rewrite of the
   collect→analyze→save contract.
3. **The inventory is derived, never authoritative for a scan.** A scan's own
   assets/findings remain the source of truth for that scan; the inventory is an
   aggregate view built from them.
4. **Honest "gone" semantics.** An asset is only marked `gone` when a scan that
   *actually covered its kind* completed without seeing it — never off a partial
   scan, a passive-only scan, or a subscan. Silence must not be read as absence
   (mirrors the WAF-coverage honesty contract).
5. **Single-user.** No per-user asset ownership / RBAC — one operator owns the
   whole inventory (see `docs/DECISIONS.md`).

## 3. Architecture — a persistent layer on top (Option B)

Two candidate shapes were considered:

- **Option A — refactor** the existing `Subdomain/IPAddress/Port/URL` to be
  domain-scoped (unique per domain, not per session). Purest, but it rewrites
  every tool's save path and needs a heavy data migration. **Rejected** for v1
  (high blast radius, violates principle 2).
- **Option B — inventory layer (chosen).** Keep per-scan assets as the scan's
  snapshot; add a persistent `Asset` model that a rollup step populates at
  finalize. Low risk, incremental, principle-2-clean.

New app: **`apps/core/asset_inventory/`** (label `asset_inventory`), peer of
`insights` — a derived-analytics layer, not a registry tool.

```
scan finalize ──► rollup step ──► Asset inventory (persistent, domain-scoped)
   (per-scan          (upsert +        │
    assets, as         gone-mark)      ├─ /api/assets/         → AssetsPage
    today)                             └─ /api/assets/<id>/    → AssetDetailPage
```

## 4. Component I1 — the persistent `Asset` model

```python
class Asset(models.Model):
    domain      = FK(Domain, on_delete=CASCADE)
    kind        = CharField(choices=["subdomain", "ip", "port", "url"])
    key         = CharField()   # "api.example.com" | "1.2.3.4" | "1.2.3.4:443" | "https://api.example.com/x"
    first_seen  = DateTimeField()
    last_seen   = DateTimeField()
    status      = CharField(choices=["active", "gone"], default="active")
    last_scan   = FK(ScanSession, null=True, on_delete=SET_NULL)
    extra       = JSONField(default=dict)   # service, is_web, technologies, cdn, …
    class Meta:
        constraints = [UniqueConstraint(fields=["domain", "kind", "key"],
                                        name="uniq_asset_per_domain")]
        indexes = [Index(fields=["domain", "kind", "status"])]
```

- `key` is the stable identity within `(domain, kind)`. Normalise on write
  (lowercase host, strip trailing dot, canonical `ip:port`, canonical URL).
- v1 stores only `first_seen`/`last_seen`. A later **`AssetObservation(asset,
  scan, seen_at)`** table adds a full per-scan timeline if wanted — deferred.
- Deletion: cascades from `Domain` (matches existing asset-cascade rule).

## 5. Component I2 — rollup at finalize

A new `@DBOS.step` invoked from `_finalize_session` (after `build_insights`,
before/independent of AI), fail-graceful (never breaks a scan):

```
rollup(session):
    if session is a subscan: return          # subscans refine, they don't redefine the surface
    covered_kinds = kinds the run's tools actually produce
    for each session asset (subdomain/ip/port/url):
        upsert Asset(domain, kind, key):
            first_seen = min(existing, now); last_seen = now
            status = "active"; last_scan = session; merge extra
    if session.status == "completed":         # honest gone-marking (principle 4)
        for kind in covered_kinds:
            Asset(domain, kind, status=active) NOT seen this scan → status = "gone"
```

- **Never** gone-marks a kind the scan didn't cover, nor on `partial`/`failed`.
- Idempotent: re-running finalize re-upserts to the same state.
- Reuses the delta/coverage machinery's "seen this scan" set.

## 6. Component I3 — Finding ↔ Asset linkage (the pivot enabler)

Add `Finding.asset = FK(Asset, null=True, on_delete=SET_NULL)`, resolved during
the rollup from the finding's existing anchors:

- `Finding.port` → the `port` Asset (`ip:port`); `Finding.url` → the `url` Asset;
  else parse `Finding.target` (hostname or `ip:port`) → matching Asset.
- Nullable and best-effort: an unresolvable target leaves `asset=None` (the
  finding still works exactly as today). This is what makes "all findings on this
  asset, across scans" a single indexed query.

## 7. Component I4 — API

`apps/core/asset_inventory/api.py`, `Router(auth=JWTAuth())`, mounted at
`/api/assets/`:

```
GET /api/assets/            paginated inventory; filters ?domain= &kind= &status= &q=
                            each row: key, kind, domain, status, first/last_seen,
                            {critical,high,medium,low,info} finding counts
GET /api/assets/<id>/       detail: metadata + extra, finding list (current +
                            historical), scan timeline where the asset was seen
GET /api/assets/summary/    (optional) totals by kind/status for the dashboard
```

Flat JSON, same envelope-less shape and error format as the rest of the API.

## 8. Component I5 — Frontend

- **New `Assets` nav item** (in `Layout.jsx`, between `Scans` and `Findings`).
- **`AssetsPage`** (`/assets`) — inventory table (key, kind, domain, status,
  first/last-seen, per-severity chips) with the standard filter/search/pagination
  pattern; `useQuery(['/api/assets', …])`.
- **`AssetDetailPage`** (`/assets/:id`) — asset metadata, `first_seen`/`last_seen`/
  `status`, finding history, and a scan-seen timeline.
- **Cross-links:** ScanDetail asset rows → AssetDetail; Findings rows → their
  asset; DomainDetail → that domain's assets.
- All react-router-dom + react-query; no new frontend deps.

## 9. Backfill

A data migration builds the inventory from existing session-scoped assets:
dedupe across all historical scans per domain → `first_seen` = earliest scan that
saw it, `last_seen` = latest, `status` from the domain's most recent complete
scan. Runs once; idempotent if re-applied.

## 10. Non-goals / explicitly out of scope

- **No Option-A refactor** of the session-scoped asset models.
- **No per-user ownership / RBAC / assignment** (single-user app).
- **No manual asset CRUD** — the inventory is scan-derived only (no hand-adding
  assets in v1).
- **No `AssetObservation` full timeline** in v1 (`first_seen`/`last_seen` only).
- **No change to scan execution, tool contracts, or the Finding lifecycle.**

## 11. Suggested sequencing for the implementation plan

1. `Asset` model + I2 rollup at finalize + I3 `Finding.asset` + backfill
   migration (+ tests: upsert, honest gone-marking, dedup, resolver).
2. `/api/assets/` endpoints (list/detail/summary) (+ API tests).
3. `AssetsPage` + `AssetDetailPage` + nav + cross-links (+ Vitest).
4. Docs: DESIGN.md (new inventory layer + UX model), CLAUDE.md (module +
   endpoints + tests), README, CHANGELOG. Definition-of-done: a new
   `check_type` is not added here, but any new report surface must stay in sync.

Each step is independently shippable; with the inventory empty, the app behaves
exactly as today.

## 12. Open decisions for the team

1. **`first_seen/last_seen` only vs. a full `AssetObservation` timeline** — v1
   proposes the former; is per-scan history worth the extra table now?
2. **`gone` vs. delete** — keep `gone` assets forever (surface history) or prune
   after N absent scans? Proposal: keep, with a `status` filter.
3. **Ports/URLs as first-class assets vs. attributes of a host** — the model
   treats each as its own `Asset` row (`kind`); acceptable, or should ports/URLs
   nest under their host in the UI only?
4. **Dashboard integration** — add an "assets: N active / M gone" KPI + a
   new-assets-this-scan delta, or keep the inventory a separate page for v1?
5. **Exposure Score** — should the score factor in `gone`-but-recently-active
   assets, or stay finding-only? (Proposal: finding-only for v1.)
