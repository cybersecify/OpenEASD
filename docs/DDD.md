# DDD.md — OpenEASD through a Domain-Driven Design lens

This document frames OpenEASD's architecture in **Domain-Driven Design** terms:
the ubiquitous language, the core domain, bounded contexts, aggregates, entities
vs value objects, domain events, and the anti-corruption layer.

It is a **companion lens, not a competing design.** It sits alongside
[`DESIGN.md`](DESIGN.md) (layers/tiers, flow, apps) and [`DECISIONS.md`](DECISIONS.md)
(rationale): where those describe the architecture *structurally*, this describes the
same system in *domain-modeling* terms. **The running code is the source of truth**;
these documents — this one included — describe it, and when any of them drifts from
the code, the code wins and the doc is corrected. The single governing decision this
whole document rests on is **[D-017](DECISIONS.md#d-017--architecture-north-star-domain-centric-api-driven-ui-agnostic)**:

> The backend stores **facts, relationships, execution state, and normalized
> results**; the UI decides **how they're presented.** The model is
> **domain-centric** (the Domain is the stable center) and joined by a
> **relationship graph**, not a nested ownership tree.

---

## 1. The domain

OpenEASD's problem domain is **External Attack Surface Management (EASM)**:
continuously observing what an organization exposes to the internet for a set of
**domains**, and turning raw observations into a durable, triageable picture of
risk over time.

- **Core domain** (the differentiator): the **domain-centric fact model** — a
  deduplicated, cross-scan **asset inventory** and **issue register** whose triage
  survives re-scans, plus the **relationship graph** that lets one backend answer
  scan-, asset-, and issue-centric questions. This is where the product's value
  concentrates, and where the hardest modeling lives.
- **Supporting subdomains**: the **scan pipeline** (13 phases of tools),
  **durable orchestration** (DBOS), **scheduling**, **reporting**, **notifications**.
- **Generic subdomains**: auth (JWT), the individual third-party scanners
  (subfinder, nuclei, nmap, …), PDF rendering. These are bought/borrowed, wrapped,
  and kept at arm's length.

The strategic bet (D-017): invest design effort in the **core domain** (the
persistent fact layer + graph) and keep the supporting/generic subdomains behind
clean adapters so they can change without disturbing the core.

---

## 2. Ubiquitous language

The same words are used in conversation, in the API (`/api/<term>`), in the model
names, and in this document. Precise definitions:

| Term | Meaning in OpenEASD |
|---|---|
| **Domain** | The organization-owned DNS domain (`example.com`) — the **stable subject** the system tracks over time. Persistent facts belong to it. |
| **Scan** (`ScanSession`) | One **run** of a workflow against a domain at a point in time — an *event/observation*, not the subject. Carries provenance + execution state. |
| **Workflow** | An ordered, configurable set of tool steps (e.g. "Full Scan", "Passive Scan"). The *plan* a scan executes. |
| **Phase / Phase group** | The pipeline's fixed ordering (13 phases) and the human-facing grouping ("Asset Discovery", "Web Exposure", …). |
| **Tool** | A self-registering scanning capability (30 of them) that observes the target/third-party data and emits normalized facts. |
| **Passive / Active** | Whether a tool touches the target directly (**active**, needs `DomainAuthorization`) or uses only public/third-party data (**passive**, no auth). |
| **Finding** | A **raw, per-scan** observation ("what this run saw") — provenance, prunable, idempotent on resume. |
| **Issue** | The **persistent, cross-scan** thing a Finding is an occurrence *of*. Carries **triage status** that survives re-scans. |
| **Asset** (inventory) | A **persistent, deduplicated** piece of attack surface (subdomain / IP / port / URL) scoped to a domain, with first/last-seen + status. |
| **Subdomain / IPAddress / Port / URL** | **Raw, per-scan** asset rows tied to a `ScanSession` (distinct from the persistent `Asset`). |
| **Promote / Rollup** | The finalize-time step that turns raw scan rows into persistent facts (`Finding → Issue`, raw assets → `Asset`). |
| **Delta / Change** | A scan-to-scan difference (new/resolved/changed). |
| **Exposure score / grade** | A per-scan risk summary derived from findings. |
| **Triage** | The human lifecycle on an Issue/Finding (open / resolved / false-positive / accepted). Lives on the **persistent** layer. |
| **Authorization** (`DomainAuthorization`) | An explicit attestation that unlocks **active** scanning of a domain. |

If a word isn't in this table, it isn't part of the domain language yet — add it
here before adding it to the code.

---

## 3. Bounded contexts

OpenEASD's contexts map onto the code layers (see DESIGN.md §layers). Each has its
own responsibility and its own vocabulary; they integrate through **stored facts +
the API contract**, never by reaching into each other's models.

```
┌───────────────────────────────────────────────────────────────────────┐
│ CONSOLE  (application / presentation services)                         │
│   dashboard · insights · reports · notifications · ai · credentials    │
│   api  ── the one published contract (Django Ninja, JWT, flat JSON)    │
├───────────────────────────────────────────────────────────────────────┤
│ ENGINE   (orchestration / execution)                                   │
│   scans (pipeline orchestrator) · workflows (runner + registry)        │
│   durable (DBOS adapter) · scheduler · service_detection               │
├───────────────────────────────────────────────────────────────────────┤
│ DATA     (the domain model — the core)                                 │
│   domains │ assets · web_assets · findings   (raw, scan-scoped)        │
│           │ asset_inventory · issues         (persistent, domain-centric)│
├───────────────────────────────────────────────────────────────────────┤
│ TOOLS    (30 self-registering scanner apps — anti-corruption layer)    │
│   collector → analyzer → scanner  (normalize external output → facts)  │
└───────────────────────────────────────────────────────────────────────┘
```

- **Data** is the **model context** — the ubiquitous language made concrete. It
  owns the entities and the two-layer split. It is the only context whose changes
  ripple everywhere, so it's guarded most carefully.
- **Engine** is the **execution context** — it *drives* the domain (runs scans,
  schedules, resumes) but stores no domain facts of its own beyond execution state.
- **Console** is the **application context** — it *reads* facts and presents them
  (KPIs, reports, alerts, AI). It contains no scanning logic.
- **Tools** are 30 small contexts, each an **anti-corruption layer** (§8) around
  one external scanner. They translate a scanner's private vocabulary into the
  shared `Finding`/`Asset` language and never talk to each other.

---

## 4. Aggregates & consistency boundaries

This is the heart of the model. OpenEASD has **two aggregates**, deliberately kept
separate — this *is* the raw-vs-persistent, two-layer design of D-017 expressed in
DDD terms.

### Aggregate A — the Scan (raw, scan-scoped)

```
ScanSession                         ← AGGREGATE ROOT (identity: uuid)
 ├── Finding            (raw)        ← entity, identity within the session
 ├── Subdomain                      ← entity
 ├── IPAddress                      ← entity
 ├── Port                          ← entity
 └── URL                           ← entity
```

- **Consistency boundary**: one scan. Written transactionally per phase-group step,
  **idempotent on resume** (a re-run tool deletes its own stale rows first — no
  duplicates), and **prunable** by retention.
- **Meaning**: *provenance* — "what this run saw." It is disposable by design.

### Aggregate B — the Domain (persistent, domain-centric)

```
Domain                              ← AGGREGATE ROOT (identity: name)
 ├── Asset  (asset_inventory)       ← entity, identity (domain, kind, key)
 │      first_seen / last_seen / status
 └── Issue                          ← entity, identity issue_key within domain
        status (TRIAGE — the lifecycle lives here)
```

- **Consistency boundary**: one domain. Written by **upsert** at finalize.
- **Meaning**: the *canonical cross-scan truth* + the triage lifecycle. It
  **outlives** any scan.

### How the two aggregates relate — reference by identity, not containment

Per DDD's aggregate rule, the two aggregates **do not nest**; they reference each
other and are updated in **separate transactions**:

- `Finding.session` → the Scan aggregate root (FK)
- `Finding.asset` → an `Asset` in the Domain aggregate (FK — *references*, doesn't own)
- `Issue.domain` / `Asset.domain` → the Domain aggregate root (FK)
- `ScanSession.domain` is a **string**, not a FK — a scan names its domain but is
  not *owned* by the Domain aggregate. (Two aggregate roots don't hard-own each other.)

The bridge between them is a **domain event**, not a transaction (§6): **promote at
finalize** reconciles Aggregate A into Aggregate B. Between the two, the layers are
**eventually consistent** — a deliberate, documented trade (see DESIGN.md flow ③).

> **Why two aggregates?** A single nested `Domain → Scan → Finding → Asset`
> aggregate would force one transaction/lifecycle on facts that have *different*
> lifecycles: raw scan data is bulky + disposable; inventory + triage are canonical
> + permanent. Splitting them is what lets retention prune scans while triage
> survives. See the full pros/cons in DECISIONS.md §D-017.

---

## 5. Entities vs value objects

**Entities** (identity + lifecycle; equality by id):

- `Domain` — id = name.
- `ScanSession` — id = uuid; lifecycle = `pending → running → completed/partial/failed/cancelled`.
- `Finding` — id within its session.
- `Asset` — id = `(domain, kind, key)`; lifecycle = `active/gone` via first/last-seen.
- `Issue` — id = `issue_key(source, check_type, title, target)` within a domain;
  lifecycle = triage `status`.
- Raw `Subdomain / IPAddress / Port / URL` — ids within a session.

**Value objects** (no identity; defined wholly by their attributes; immutable in
spirit):

- `severity` (`critical/high/medium/low/info`), `status` enums.
- `issue_key` — a **computed identity value** (a deterministic hash of the finding's
  defining attributes) that gives an Issue its stable cross-scan identity. A textbook
  value object doing identity work.
- `exposure_score` + `grade` — a derived risk summary.
- Coverage fields (`waf_vendor`, `endpoints_probed/blocked`), CWE mapping, EPSS/KEV
  enrichment on a finding's `extra` — descriptive, id-less.
- `extra` (JSON) — tool-specific attributes carried as a value bag.

**Rule of thumb applied here:** if we ask "is this the *same* one as before?" it's
an entity (Domain, Asset, Issue). If we only ask "what does it *say*?" it's a value
object (severity, score, coverage).

---

## 6. Domain events

The system's behavior is a sequence of domain events. The pivotal one is
**ScanFinalized**, which triggers the promote from raw to persistent facts.

| Event | Raised by | Consequence |
|---|---|---|
| **ScanRequested** | `POST /api/scans/start/`, scheduler cron, or AI agent | `create_scan_session(domain)` + enqueue the durable workflow |
| **ScanStarted** | `run_scan` workflow (worker) | status → `running`; pipeline begins |
| **PhaseCompleted** | workflow runner | checkpointed DBOS step; heartbeat `last_progress_at` |
| **ScanFinalized** | `_finalize_session` | count → coverage → status; **then fires the promote + downstream chain ↓** |
| ↳ **AssetsPromoted / IssuesPromoted** | rollup functions | raw rows upserted into `Asset` inventory + `Issue` register |
| ↳ **DeltaDetected / CoverageRegression** | delta + coverage checks | change feed + regression findings |
| ↳ **InsightsBuilt** | insights builder | exposure score + summaries |
| ↳ **AIPostScanCompleted** | AI hooks (if enabled) | triage + summaries (never writes Findings) |
| ↳ **AlertDispatched** | notifications | Slack/Teams (idempotent on replay) |
| ↳ **AgentStepDecided** | AI orchestrator | bounded subscan / flag / done |

The event ordering is fixed and encoded in `_finalize_session` (see DESIGN.md scan
flow). "Promote" is the event that crosses the aggregate boundary of §4.

---

## 7. Repositories & domain services

- **Repositories** — the Django ORM managers are the repositories. Notable
  query-side helpers act as repository methods over the aggregates, e.g.
  `latest_session_ids()` (the "current" covering scan per domain). Reads for the API
  go through these; the API layer never hand-rolls cross-aggregate SQL.
- **Domain services** (logic that doesn't belong to a single entity):
  - **Pipeline runner** (`workflows`) — orchestrates tools in phase order; the
    scan-execution domain service.
  - **Promote / rollup** (`issues.rollup.rollup_session_issues`, the asset-inventory
    rollup) — reconciles Aggregate A → Aggregate B. Idempotent + fail-graceful.
  - **Scoring** (`insights.scoring`) — computes exposure score/grade.
  - **AI triage / orchestration** (`ai`) — ranks findings, runs a bounded agent;
    read-only w.r.t. domain facts.
- **Factories** — `create_scan_session` / `create_subscan_session` construct a valid
  Scan aggregate root (assigning the default workflow, stamping provenance).

---

## 8. Anti-corruption layer (the tools)

The 30 tool apps are the model's boundary against the messy outside world, and each
is a clean **anti-corruption layer** with a fixed three-part shape:

```
collector.py  — run the external binary / call the external API → raw bytes/JSON
analyzer.py   — TRANSLATE that private vocabulary into the ubiquitous language
                (build shared Finding / Asset objects; normalize, dedup, redact)
scanner.py    — thin orchestrator: collect → analyze → save
```

Invariants that keep the ACL clean (enforced by convention + tests):

- **Tools never import each other.** Shared data flows only through the `Data`
  context (`findings`, `assets`, `web_assets`). This prevents one scanner's model
  from leaking into another's.
- **`models.py` is empty** in a tool app — a tool owns *no* persistent model; it
  only writes shared facts. (A tool that needed its own table would be a new context.)
- **Self-registration** via `AppConfig.tool_meta` — the registry auto-discovers
  capabilities; the core never hard-codes a tool. Adding/removing a capability
  doesn't touch the core model.
- **Normalization is mandatory**: severity mapping, CWE mapping, secret redaction,
  and public-IP filtering all happen in the analyzer, so downstream contexts see
  only clean domain language, never raw tool output.

The **execution engine is also kept behind an adapter**: DBOS is isolated to
`engine/durable` behind a `@durable_task` port (hardening item H6), so the durable-
execution technology can change without touching the domain or the pipeline.

---

## 9. Why this shape (strategic summary)

- **Domain-centric, not scan-nested** → the Domain is the aggregate root of the
  canonical facts, so continuity/dedup/triage persist across scans. A scan-nested
  tree would bind facts to a disposable event.
- **Two aggregates, eventually consistent via a promote event** → raw provenance and
  canonical truth have different lifecycles (prunable vs permanent); separating them
  is what makes retention + durable triage possible at once.
- **Relationship graph, not containment** → independent entities joined by edges
  (`Scan discovers Asset`, `Finding affects Asset`, `Finding promoted to Issue`) let
  one backend serve scan-/asset-/issue-centric views with no schema change.
- **Tools as anti-corruption layers** → 30 external scanners are wrapped so their
  vocabularies never pollute the core model; capabilities are pluggable.
- **UI-agnostic contract** → the API is the published language; any client (SPA, CLI,
  another service) consumes the same facts. Presentation is not a domain concern.

---

## 10. Cross-references

Read in flow order (see [`README.md`](README.md) for the full reading path):

- **Product framing** — [`PRD.md`](PRD.md) (what/why).
- **Structural architecture** — [`DESIGN.md`](DESIGN.md) (layers/tiers, the flow
  diagram, the app tables, the scan pipeline).
- **Rationale + trade-offs** — [`DECISIONS.md`](DECISIONS.md), esp. **D-017**
  (domain-centric north star) and the raw-vs-persistent split.
- **API contract** — [`API.md`](API.md) (conventions) + the live OpenAPI at `/api/docs`.
- **Conventions** — [`CODING_STANDARDS.md`](CODING_STANDARDS.md).

This DDD lens and the structural docs are **companions describing one system**; the
**running code is the source of truth**. If any of them drifts from the code, correct
the doc to match — never the reverse.
