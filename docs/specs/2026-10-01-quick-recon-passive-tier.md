# Quick Recon — Passive-Tier Formalization — Design Spec

> **Status:** Proposed. Design agreed via brainstorming (purpose = a Quick-Recon
> scan mode; light set = the apex-only four). Built to this contract.

**Goal:** Formalize a **light / deep** split *within* the passive tool set and
back it with a predefined **"Quick Recon"** workflow — a no-auth first look that
runs only the four apex-scoped, fast, keyless-capable passive tools and finishes
in seconds, versus the full passive scan (which fans out into minutes of
subdomain/CT/archive enumeration).

**Owner:** OpenEASD core (`apps/core/engine/workflows`). **Depends on:** the
existing passive/active classification (`tool_meta["active"]`,
`is_passive_tool_set`) and the predefined-workflow pattern (migration
`0022_create_passive_scan_workflow.py`). **Scope:** additive — one new optional
`tool_meta` flag (safe default), one registry accessor + helper, one non-default
workflow (data migration), a drift-lock test, and docs. **No** change to Full
Scan, Passive Scan, the authorization boundary, or any tool's behavior.

---

## 1. Motivation

The platform already draws one line through its tools — **passive vs active**,
the authorization boundary. But "passive" spans a wide cost range:

- **Apex-only, fast** — `domain_security` (DNS/DNSSEC/email-auth/RDAP),
  `dns_history`, `hudson_rock`, `breach_check`. A handful of lookups against the
  apex (or a third-party API keyed on the apex). No discovery fan-out. Nothing
  downstream depends on them. Seconds.
- **Heavy enumeration** — `tldsquatting` (~900 candidates + hundreds of DNS +
  homepage fetches), `subfinder`, `historical_urls`, `cloud_assets`,
  `asn_discovery`, `github_recon`. Minutes.
- **BYOK-mandatory** — `github_secrets` (no-op without `GITHUB_TOKEN`; GitHub
  code-search + gitleaks).
- **Dependent** — `dnsx`, `alterx`, `shodan`, `cve_intel`, `asn_cluster`:
  produce nothing standalone (need resolved subdomains / IPs / upstream
  findings).

There is no way today to ask for *just the instant read* — a user who wants a
quick posture + credential-exposure snapshot must run the full Passive Scan and
wait out the enumeration. This spec adds a **light tier** and the Quick Recon
workflow it backs.

The light/deep split is deliberately **its own axis**, distinct from
`runner._LOW_MEM_PARALLEL_SAFE` (a memory/IO axis — which tools are safe to run
concurrently on a 1GB box; it mixes passive and active and includes the heavy
`tldsquatting`). That set is **not** touched by this spec.

---

## 2. The light set

Quick Recon contains exactly these four passive tools:

| Tool | Phase | Why light |
|---|---|---|
| `domain_security` | 1 | DNS/DNSSEC/CAA/email-auth + RDAP via public resolvers — a fixed, small set of lookups against the apex. |
| `dns_history` | 1 | One passive-DNS API call (BYO endpoint; no-op if unset). |
| `hudson_rock` | 2 | One keyless Cavalier API call (aggregate counts). |
| `breach_check` | 2 | One keyless XposedOrNot (or BYOK HIBP) API call (aggregate counts). |

All four are already `active=False` (passive), so Quick Recon inherits the
existing no-auth bypass for `schedule_type="now"` scans with **zero new
authorization code**. None of them need upstream discovery output, so the
workflow is a flat, fast phase-1/phase-2 run.

**Explicitly excluded** and why: `tldsquatting` / `subfinder` /
`historical_urls` / `cloud_assets` / `asn_discovery` / `github_recon` (heavy
enumeration — minutes); `github_secrets` (BYOK-mandatory, slower, usually
empty); `dnsx` / `alterx` / `shodan` / `cve_intel` / `asn_cluster` (dependent —
produce nothing without upstream assets/findings).

---

## 3. The classification (`tool_meta` + registry)

Mirror the `active` flag exactly:

- **`tool_meta["quick_recon"]`** — optional boolean, set `True` on the four
  light tools. Named for what it powers so the metadata and its purpose stay
  tied together.
- **Registry** (`apps/core/engine/workflows/registry.py`) stores it with a
  **safe default of `False`** — the same defensive-default discipline as
  `active` defaulting `True`: an unclassified tool is **not** light, so a future
  tool can never silently bloat the fast mode.
- **New accessor `get_tool_quick_recon() -> dict[str, bool]`** — tool → flag,
  shaped like `get_tool_active()`.
- **New helper `light_passive_tools() -> set[str]`** — the single source of
  truth for the taxonomy: tools that are **passive AND `quick_recon`**. From it:
  - *light passive* = `light_passive_tools()`
  - *deep passive* = passive tools **not** in `light_passive_tools()`
  - active tools have **no** tier (the flag is meaningless on them; the helper's
    passive-AND gate makes a stray `quick_recon=True` on an active tool a no-op
    rather than a hole).

One meaning, derived in one place. No tri-state enum.

---

## 4. The Quick Recon workflow (data migration)

A new migration `0036_create_quick_recon_workflow.py`, shaped exactly like
`0022_create_passive_scan_workflow.py`:

- Creates a predefined, **non-default** `Workflow` named **"Quick Recon"** with
  the four light tools as enabled `WorkflowStep`s in pipeline-phase order.
- Idempotent (`if Workflow.objects.filter(name="Quick Recon").exists(): return`)
  with a matching reverse that deletes it.
- Description makes the no-auth, seconds-not-minutes framing explicit.

Full Scan (active, gated, default) and Passive Scan (all-passive, non-default)
are unchanged.

---

## 5. Drift lock (tests)

The flag (§3) and the workflow (§4) are two representations of the same set, so
a test binds them — the discipline of
`test_default_workflow::test_full_scan_covers_every_registered_tool`:

- **`test_quick_recon.py`**
  - The "Quick Recon" workflow's tool set **equals** `light_passive_tools()` —
    every light tool is in the workflow and the workflow holds nothing else
    (prevents flag↔workflow drift in both directions).
  - Every tool in the workflow is **passive** (`is_passive_tool_set` is True) —
    so Quick Recon can never lose its no-auth property.
  - `light_passive_tools()` is exactly the expected four (locks the membership
    decision of §2).
- **`test_workflow_registry` (or extend the existing registry test)**
  - `get_tool_quick_recon()` returns the flag for each tool.
  - An unclassified / absent flag defaults to `False`.
  - A stray `quick_recon=True` on an **active** tool does **not** appear in
    `light_passive_tools()` (the passive-AND gate holds).

---

## 6. Exposure (backend only)

- The tier is added to the `/api/workflows/tools/` response (alongside the
  existing `active` flag) so the SPA *can* badge light vs deep later.
- **Out of scope here:** the React badge itself — per the project's
  backend-first / frontend-last rule, the UI pass is a follow-up, not part of
  this change. No new endpoint; no change to any existing response's existing
  fields (purely additive key).

---

## 7. Docs

- **CLAUDE.md** — document the Quick Recon workflow next to Passive Scan; add
  the light/deep passive definition; add a line to the "definition of done for
  adding a tool" to set `quick_recon` when a new passive tool is apex-scoped and
  fast.
- **`docs/03-system.md`** — note the light/deep passive split (system altitude).
- **No PRD / DDD change** — this is a system/technical classification, not a
  product capability or domain concept (per the docs-layer-altitude rule).

---

## 8. Design invariants (guarded by tests)

- The `quick_recon` flag defaults `False`; an unclassified tool is never light.
- `light_passive_tools()` = passive **AND** `quick_recon` — a stray flag on an
  active tool is a no-op, never an authorization hole.
- The "Quick Recon" workflow's membership equals `light_passive_tools()` exactly
  (no drift either way) and is entirely passive (no-auth preserved).
- Full Scan, Passive Scan, the authorization boundary, and every tool's runtime
  behavior are unchanged (additive-only).

---

## 9. Non-goals

- Reclassifying or touching `runner._LOW_MEM_PARALLEL_SAFE` (separate memory/IO
  axis).
- A React badge or any frontend change (documented follow-up).
- Making Quick Recon a default or scheduled workflow (it is a manual, on-demand
  mode, like Passive Scan).
- Any new "deep passive" workflow — "deep" is a derived descriptor, not a
  shipped scan mode.
