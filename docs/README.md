# OpenEASD documentation

These docs are meant to be read **top-down**, from *why we're building it* to *how
it's coded*. Each stage narrows scope: intent → domain language → architecture →
detailed design → interface → implementation.

## Reading order (the design flow)

| # | Stage | Document | Answers |
|---|---|---|---|
| 1 | **Product** | [`PRD.md`](PRD.md) | What are we building, for whom, and why? |
| 2 | **Domain model (DDD)** | [`DDD.md`](DDD.md) | The ubiquitous language, bounded contexts, aggregates, entities, and domain events. |
| 3 | **System design** | [`DESIGN.md`](DESIGN.md) | The structural architecture — layers/tiers, the fact-flow, the apps, the 13-phase scan pipeline. |
| — | *Rationale* | [`DECISIONS.md`](DECISIONS.md) | *Why* the design is the way it is (ADRs, incl. **D-017** — the domain-centric north star). Read alongside 2–3. |
| 4 | **Technical design** | [`specs/`](specs/) | Per-feature detailed designs (e.g. asset-centric inventory, WAF coverage, the producer→queue→consumer hardening plan). |
| 5 | **API contract** | [`API.md`](API.md) + live OpenAPI at `/api/docs` | The published interface: auth, error shape, pagination, versioning. |
| 6 | **Coding** | [`CODING_STANDARDS.md`](CODING_STANDARDS.md) | Conventions every change follows + open review findings. |

## Operational references (beside the flow, not in it)

- [`DEVELOPMENT.md`](DEVELOPMENT.md) — local dev, the deploy/promote/rollback flow.
- [`SCAN_OPERATIONAL_LEARNINGS.md`](SCAN_OPERATIONAL_LEARNINGS.md) — memory/OOM tuning,
  scan-profile behavior, hard-won operational lessons.

## The one rule that ties them together

The **running code is the source of truth.** Every document here — PRD through DDD to
the specs — *describes* the system; when a doc drifts from the code, the code wins and
the doc is corrected, never the reverse. (The one exception is the OpenAPI spec at
`/api/docs`, which is *generated from* the code and so cannot drift.)

For contributor workflow (branching, commits, PRs, tagging), see the root
[`CLAUDE.md`](../CLAUDE.md).
