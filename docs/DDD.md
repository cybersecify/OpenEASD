# DDD.md — OpenEASD through a Domain-Driven Design lens

This document describes OpenEASD's **domain model** in Domain-Driven Design terms:
the ubiquitous language, the core domain, bounded contexts, aggregates, entities vs
value objects, and domain events.

It is written in **pure domain terms** — it deliberately names no technology, no
framework, no storage mechanism, and no source files. It describes *what the model
is*, not *how it is built*. For the implementation mapping (layers, storage, the
execution engine, the API), see [`DESIGN.md`](DESIGN.md); for the decisions and
trade-offs behind the model, see [`DECISIONS.md`](DECISIONS.md).

The one governing decision this rests on is
**[D-017](DECISIONS.md#d-017--architecture-north-star-domain-centric-api-driven-ui-agnostic)**:

> The system stores **facts, relationships, and the state of work**; presentation
> decides **how those facts are shown.** The model is **domain-centric** — the Domain
> is the stable center — and entities are joined by a **relationship graph**, not a
> nested ownership tree.

This lens and the structural docs are **companions describing one system**; the
running system is the source of truth, and any doc that drifts from it is corrected
to match — never the reverse.

---

## 1. The domain

OpenEASD's problem domain is **External Attack Surface Management (EASM)**:
continuously observing what an organization exposes to the internet across a set of
**domains**, and turning raw observations into a durable, triageable picture of risk
that holds up *over time*.

- **Core domain** (the differentiator): the **domain-centric fact model** — a
  deduplicated, cross-scan record of *assets* and *issues* whose triage survives
  re-observation, joined by a *relationship graph* that lets the same facts be read
  from several angles. This is where the product's value concentrates and where the
  hardest modeling lives.
- **Supporting subdomains**: running an observation (the scan pipeline), scheduling
  observations, reporting, and notifying.
- **Generic subdomains**: identity/authentication, the individual third-party
  scanning techniques, document rendering — necessary, but not distinctive.

The strategic bet (D-017): invest modeling effort in the **core domain** and keep the
supporting and generic subdomains at arm's length behind clean boundaries, so they can
change without disturbing the core.

---

## 2. Ubiquitous language

The same words are used in conversation, in the model, and in this document. Precise
definitions:

| Term | Meaning |
|---|---|
| **Domain** | An organization-owned internet domain — the **stable subject** the system tracks over time. Canonical facts belong to it. |
| **Scan** | One **observation** of a domain at a point in time — an *event*, not the subject. It records what that observation saw and how far it got. |
| **Workflow** | The *plan* an observation follows: an ordered, configurable set of techniques (e.g. "Full", "Passive"). |
| **Phase / Phase group** | The fixed ordering of the observation and the human-facing grouping of techniques ("Asset Discovery", "Web Exposure", …). |
| **Tool** | A single **observation technique** — one way of looking at the target or at public data. |
| **Passive / Active** | Whether a technique touches the target directly (**active** — requires authorization) or uses only public / third-party knowledge (**passive** — no authorization). |
| **Authorization** | An explicit attestation that the operator has the authority to observe a domain *actively*. It gates all active observation. |
| **Finding** | A single **raw observation** — "what this one scan saw". It is provenance: attributable to its scan, and disposable. |
| **Issue** | The **enduring thing a Finding is an occurrence of** — the same problem seen across many scans, carrying the **triage** that must persist. |
| **Asset** | An **enduring, deduplicated piece of attack surface** (a host, address, port, or web endpoint) belonging to a Domain, with when it was first and last seen and whether it's still present. |
| **Subdomain / Address / Port / Endpoint** | The **raw, per-scan** view of attack surface, attributable to a single observation (distinct from the enduring **Asset**). |
| **Promote** | Turning raw observations into enduring facts at the close of a scan (Findings → Issues, raw surface → Assets). |
| **Delta / Change** | A difference between one observation and the previous one (appeared / resolved / changed). |
| **Exposure score / grade** | A summary of a domain's risk derived from its findings. |
| **Triage** | The human lifecycle applied to an Issue (open / resolved / false-positive / accepted). It lives on the enduring layer so it survives re-observation. |

If a word isn't here, it isn't part of the domain language yet — add it here before
using it.

---

## 3. Bounded contexts

The system divides into four contexts, each with its own responsibility and its own
vocabulary. They integrate **only through shared, stored facts and the published
interface** — never by reaching into one another's internals. (Which code owns each
context is a structural concern — see [`DESIGN.md`](DESIGN.md).)

- **Domain Model** — the core. Owns the ubiquitous language made concrete: Domains,
  Scans, Findings, Assets, Issues, and the relationship graph. Its changes ripple
  outward, so it is guarded most carefully.
- **Observation** — orchestrates and runs a scan: chooses the workflow, sequences the
  phases and techniques, and can resume an interrupted observation. It *drives* the
  domain but holds no canonical facts of its own beyond the state of work in progress.
- **Reporting & Presentation** — reads facts and turns them into things people
  consume: dashboards, reports, alerts, scores, AI summaries. It contains no
  observation logic.
- **Observation Techniques** — the many individual ways of looking (each a small
  context of its own). Every technique **translates** what it sees into the shared
  domain language, and no technique depends on another (§8).

---

## 4. Aggregates & consistency boundaries

This is the heart of the model. There are **two aggregates**, deliberately kept
separate — because raw observation and enduring truth have *different lifecycles*.

### Aggregate A — the Scan (raw, point-in-time)

```
Scan                               ← aggregate root
 ├── Finding      (raw)
 ├── Subdomain
 ├── Address
 ├── Port
 └── Endpoint
```

- **Consistency boundary**: one observation. It is internally consistent as a unit,
  can be re-run without producing duplicates, and is **disposable** — it can be pruned
  once its facts have been promoted.
- **Meaning**: *provenance* — "what this one observation saw."

### Aggregate B — the Domain (enduring, canonical)

```
Domain                             ← aggregate root
 ├── Asset   (deduplicated per domain; first-seen / last-seen / present?)
 └── Issue   (carries TRIAGE — the lifecycle lives here)
```

- **Consistency boundary**: one domain.
- **Meaning**: the *canonical, cross-scan truth* and the triage lifecycle. It
  **outlives** any single observation.

### How the two relate — reference by identity, not containment

The two aggregates **do not nest**. They reference each other **by identity** and are
kept consistent **separately**:

- a Finding knows which Scan it came from, and which Asset it *affects*;
- an Asset and an Issue each know which Domain they belong to;
- a Scan merely *names* the Domain it observed — it is not *owned* by the Domain.
  (Two aggregate roots do not own each other.)

The bridge between them is a **domain event, not a single transaction**: **Promote**
(at the close of a scan) reconciles the raw aggregate into the enduring one. Between
observations, the enduring layer reflects the *last completed* scan — a deliberate,
accepted lag.

> **Why two aggregates?** One nested `Domain → Scan → Finding → Asset` aggregate would
> force a single lifecycle onto facts that have two: raw observations are bulky and
> disposable; the asset inventory and issue triage are canonical and permanent.
> Splitting them is what lets old observations be pruned while triage survives. Full
> trade-offs: [`DECISIONS.md` §D-017](DECISIONS.md).

---

## 5. Entities vs value objects

**Entities** — have identity and a lifecycle; "is this the *same* one as before?"

- **Domain** — identified by its name.
- **Scan** — identified by its own observation identity; lifecycle runs from requested
  through running to a terminal outcome (complete / partial / failed / cancelled).
- **Finding** — identified within its Scan.
- **Asset** — identified by *(domain, kind, key)*; lifecycle is present → gone, tracked
  by first- and last-seen.
- **Issue** — identified by a stable **issue identity** derived from a finding's
  defining traits, within a domain; lifecycle is its triage status.

**Value objects** — no identity; defined wholly by their attributes; "what does it
*say*?"

- **Severity** and **status** classifications.
- The **issue identity** itself — a stable value derived from a finding's defining
  traits, that gives an Issue its cross-scan sameness. A value that *does* identity
  work.
- **Exposure score** and **grade** — a derived risk summary.
- **Coverage** of an observation (what was reached vs blocked), and risk enrichments
  attached to a finding.

**Rule of thumb:** ask *"is it the same one as before?"* → entity (Domain, Asset,
Issue). Ask *"what does it say?"* → value object (severity, score, coverage).

---

## 6. Domain events

The system's behavior is a sequence of domain events. The pivotal one is **Scan
Finalized**, which triggers the promotion from raw observation to enduring fact.

| Event | Meaning |
|---|---|
| **Scan Requested** | Someone or something asked to observe a domain (a person, a schedule, or the AI agent). A new Scan is created and queued. |
| **Scan Started** | The observation began; the Scan is now in progress. |
| **Phase Completed** | A phase of the observation finished and was durably recorded, so the observation can resume from there if interrupted. |
| **Scan Finalized** | The observation reached a terminal outcome; its coverage and result are settled — **and the promotion chain below fires.** |
| ↳ **Assets Promoted / Issues Promoted** | Raw observations become enduring facts: the asset inventory is updated, and findings are promoted into the issue register. |
| ↳ **Delta Detected** / **Coverage Regressed** | Differences from the previous observation, and any drop in how much could be reached, are recorded. |
| ↳ **Insights Built** | The exposure score and summaries are computed. |
| ↳ **Post-scan Analysis Completed** | Optional AI triage and summaries are produced (they never create findings). |
| ↳ **Alert Dispatched** | Interested parties are notified — at most once per settled scan. |
| ↳ **Agent Step Decided** | If enabled, a bounded automated follow-up decides to observe further, flag, or stop. |

The ordering is fixed: **Promote** is the event that crosses the boundary between the
two aggregates of §4.

---

## 7. Domain services

Some behavior belongs to no single entity — it coordinates several. These are domain
services, described here by *what they do*:

- **Observation orchestration** — runs a scan's techniques in the right order and
  records how far it got.
- **Promotion** — reconciles a finished scan's raw observations into the enduring
  asset inventory and issue register. It is safe to repeat and never fails the scan.
- **Scoring** — turns a domain's findings into an exposure score and grade.
- **Post-scan analysis** — ranks findings and can run a bounded automated follow-up;
  it only *reads* the domain facts, never authors them.
- **Scan creation** — constructs a valid Scan (assigning its plan and stamping its
  provenance), including follow-up scans requested by the automated agent.

Retrieving aggregates (a domain's current assets, its open issues, the latest
observation) is done through **collection-like queries** over each aggregate; readers
go through these rather than assembling facts by hand.

---

## 8. The boundary against the outside (anti-corruption)

Every observation technique sits at the edge between the messy outside world and the
clean domain model, and each acts as an **anti-corruption layer**:

- it **observes** — runs its technique against the target or against public knowledge;
- it **translates** — turns what it saw into the shared domain language (Findings and
  the raw attack-surface view), normalizing severities, mapping to risk categories,
  and redacting anything sensitive *before* it enters the model;
- it **records** — writes only shared domain facts.

The invariants that keep this boundary clean:

- **Techniques never depend on each other.** They integrate only through shared facts,
  so no technique's private notion of the world leaks into another's.
- **A technique owns no facts of its own** — it contributes to the shared model and
  nothing more. A capability that needed its own records would be a new context.
- **Techniques are pluggable.** Adding or removing one is a capability change, not a
  change to the core model.
- **Normalization is mandatory**, so everything downstream sees clean domain language,
  never raw external output.

The **execution engine is likewise held behind a boundary**, so the machinery that
runs observations can change without disturbing the domain or the observation plan.

---

## 9. Why this shape (strategic summary)

- **Domain-centric, not scan-nested** — the Domain is the root of the canonical facts,
  so continuity, deduplication, and triage persist across observations. A scan-nested
  hierarchy would bind facts to a disposable event.
- **Two aggregates, reconciled by a promotion event** — raw provenance and canonical
  truth have different lifecycles; separating them is what makes both pruning old
  observations *and* durable triage possible at once.
- **A relationship graph, not containment** — independent entities joined by edges
  (*Scan discovers Asset*, *Scan generates Finding*, *Finding affects Asset*, *Finding
  promoted to Issue*) let the same facts be read scan-first, asset-first, or
  issue-first with no change to the model.
- **Techniques as anti-corruption layers** — the outside world's vocabularies never
  pollute the core, and capabilities are pluggable.
- **Presentation-agnostic** — facts are the published language; how they're shown is
  not a domain concern.

---

## 10. Cross-references

Read in flow order (see [`README.md`](README.md) for the full reading path):

- **Product framing** — [`PRD.md`](PRD.md) (what / why).
- **Structural architecture & implementation mapping** — [`DESIGN.md`](DESIGN.md)
  (layers, the fact-flow, the observation pipeline, and where each context lives).
- **Decisions & trade-offs** — [`DECISIONS.md`](DECISIONS.md), esp. **D-017** and the
  raw-vs-enduring split.
- **The published interface** — [`API.md`](API.md).
- **Conventions** — [`CODING_STANDARDS.md`](CODING_STANDARDS.md).

This document stays in **domain terms**; anything about *how* the model is realized
belongs in DESIGN.md. If this lens ever disagrees with the running system, the system
is right and this file is corrected.
