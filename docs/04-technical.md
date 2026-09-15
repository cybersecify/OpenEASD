# OpenEASD — Technical Design

The **technical-design** layer of the doc flow (`01-prd` → `02-domain` →
`03-system` → **`04-technical`** → `05-api` → `06-coding`). Where
[`03-system.md`](03-system.md) describes the architecture as a whole, this layer
is where a *specific* feature or change is designed in detail before it is coded.

Detailed per-feature designs live in [`specs/`](specs/) — one spec per feature,
carrying the problem, the options considered, the chosen mechanism, and the
migration/rollout. Add a new spec here before building anything non-trivial; a
spec that drifts from the shipped behaviour is corrected like a failing test.

## Current specs

- [WAF/Block Detection & Honest Coverage Contract](specs/2026-08-16-waf-coverage-honest-scope.md)
  — classify each probe as reached/blocked/challenged/rate-limited and surface
  honest scan coverage rather than a false "clean".
- [Asset-Centric Inventory](specs/2026-09-06-asset-centric-inventory.md) — the
  persistent, deduplicated per-domain `Asset` inventory and its finalize rollup.
- [Issue Register](specs/2026-09-15-issue-register.md) — the persistent,
  cross-scan `Issue` register (Aggregate B): `check_id`/`issue_key` identity, the
  finalize rollup with triage carry-forward + auto-resolve, and the canonical
  triage write path. Sibling of the asset inventory.
- [Producer → Queue → Consumer Hardening](specs/2026-09-07-producer-queue-consumer-hardening.md)
  — the H1–H10 durability/observability plan for the scan pipeline.
- [Credential Management — UI-managed BYOK keys](specs/2026-09-09-credential-management.md)
  — the encrypted `ToolCredentials` store + `get_credential()` DB-wins-over-env
  resolver.
- [Finding-Centric UI, Grounded on Asset-Centric](specs/2026-09-12-finding-centric-ui-direction.md)
  — the direction for the finding/issue register views over the domain-centric
  backend.
