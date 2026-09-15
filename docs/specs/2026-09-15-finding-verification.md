# Finding Verification — Design Spec

> **Status:** 📝 Proposed — not yet implemented. Design agreed via brainstorming
> (mechanism, scope, trigger, and re-probe approach all decided — see §2). This is
> the design contract to build against; on implementation, update this header and
> the shipped behaviour in `03-system.md` / CLAUDE.md.

**Goal:** Move OpenEASD from *"here is a finding"* to *"here is a finding, and we
re-checked that it still reproduces."* Each medium-or-higher finding gets an honest
**verification verdict** — `verified` / `inconclusive` / `unverified` — carried onto
the enduring `Issue` and surfaced in the API + report with fresh evidence. Lower the
triage load by proving what's real, without ever dressing a maybe up as confirmed.

**Owner:** OpenEASD core. **Depends on:** the raw `Finding` layer, the
`_finalize_session` seam, the tool registry, and `DomainAuthorization`. **Builds on:**
[Issue Register](2026-09-15-issue-register.md) (the verdict lands on `Issue`) and the
existing AI layer (optional adjudication). **Inspiration:** the "prove, don't just
detect" independent-verifier pattern, adapted to OpenEASD's authorization-gated,
honest-scope, AI-off-by-default posture.

---

## 1. Motivation

Every finding today is asserted from a single observation. Scanners produce false
positives (a template fires on a benign response; a header check races a deploy; a
CVE match ignores a backport). Users then hand-triage a wall of maybes. Meanwhile
OpenEASD's whole ethos is **honest scope** — labeled partials, honest coverage,
consent gates. Verification extends that ethos to the finding itself: **re-run the
finding's own check and report whether it still reproduces**, with three states that
never overclaim.

The constraints that shape the design (all settled in brainstorming):

- **AI is off by default**, and the invariant "AI-off ⇒ no AI traces" must hold →
  the baseline verdict must be **deterministic**, AI-independent.
- **Re-probing costs time + touches the target** → **severity-gated** (medium+), and
  active re-probes are **authorization-gated** exactly like active tools.
- **Honest > clever** → a finding we didn't/couldn't check is `unverified` or
  `inconclusive`, never silently "verified".

---

## 2. Decisions (from brainstorming)

| Fork | Decision |
|---|---|
| **Mechanism** | **Deterministic re-probe (baseline) + optional AI adjudication layer.** Deterministic decides the verdict; AI annotates, never flips it. |
| **Scope** | **Severity-gated: medium/high/critical.** Info/low stay `unverified`. Threshold configurable. |
| **Trigger** | **Inline at finalize** (behind `FINDING_VERIFICATION_ENABLED`) **+ on-demand endpoints.** Active re-probes re-check `DomainAuthorization`; missing auth ⇒ `inconclusive`, never a silent target hit. |
| **Re-probe implementation** | **Approach A — per-tool verifier registry.** Each tool optionally registers a verifier in `tool_meta`; tools without one leave their findings honestly `unverified`. |

---

## 3. Verdict states

Three states, plus the transient default:

| `verification_status` | Meaning |
|---|---|
| `unverified` (default) | Not attempted — no verifier for the tool, below the severity threshold, or verification disabled. **The honest "we didn't check."** |
| `verified` | A verifier re-ran the check and it **still reproduced**. |
| `inconclusive` | A verifier ran but **could not confirm** — didn't reproduce, target unreachable, or (active check) authorization absent. Distinct from "didn't try". |

There is deliberately **no `false`/`not_a_finding`** state: a finding that no longer
reproduces is `inconclusive` (it may be intermittent, WAF-variable, or fixed) — the
human decides via triage (`false_positive`), which the verifier must never do for
them.

---

## 4. Data model

**`Finding`** gains:
- `verification_status` — CharField, choices above, default `unverified`, indexed.
- `verified_at` — DateTimeField, nullable.
- `extra["verification"]` — `{method, verdict, checked_at, evidence, detail, ai?}`
  (light schema, per the extra-JSON convention). `evidence` is the fresh re-probe
  artifact (e.g. the response snippet / cipher / DNS answer that proves it);
  `ai` (optional) is `{confidence, rationale}` from the adjudication layer.

**`Issue`** gains `verification_status` (mirrors the latest finding's verdict), set by
the issue rollup — so "verified" persists across scans on the enduring layer, exactly
like `status`/`severity` do.

Two small field-add migrations (findings, issues). No backfill — existing rows read
`unverified`.

---

## 5. Verifier contract + registry (Approach A)

- **Registration:** `tool_meta["verifier"] = "apps.<tool>.verify.verify_finding"` —
  a new optional key. The registry gains `get_tool_verifiers()` (source → callable),
  mirroring `get_tool_runners()`.
- **Location:** `apps/<tool>/verify.py`, importing only from `findings`/`assets`
  (the tool-isolation rule holds — no tool imports another).
- **Signature:** `verify_finding(finding) -> Verdict`, where `Verdict` is a small
  dataclass `{verdict: "verified"|"inconclusive", evidence: str, detail: str}` in the
  verification engine package. The verifier re-issues **just that check's** probe,
  reusing the tool's own collector helpers where possible.
- **Fail-graceful by contract:** any exception → `inconclusive` (with `detail`),
  never raises → never fails a scan.
- **Passive vs active:** a passive check's verifier re-queries the third party (no
  target contact, no auth). An active check's verifier re-probes the target and is
  gated (see §6).

**Seed coverage (first cut):** the highest-value active tools —
`web_checker` (headers/cookies/CORS), `tls_checker` (cipher/protocol/cert),
`ssh_checker`, `nuclei` (re-run the matched template), `nmap` (re-confirm the CVE
port/service). Remaining tools get verifiers incrementally; until then their findings
are honestly `unverified`. **Coverage is logged**, never silently capped.

---

## 6. Orchestrator — `apps/core/engine/verification/`

`verify_session(session, *, threshold="medium") -> None`:

1. Select findings at/above `threshold` (exclude the `scan_coverage` meta-source).
2. Group by `source`; look up each tool's verifier (`get_tool_verifiers()`).
3. **Auth gate:** if the tool is **active** and the session's domain has no active
   `DomainAuthorization`, label its findings `inconclusive`
   (`detail="verification skipped: no authorization"`) — reuse the exact check the
   API + AI agent (`gate_subscan_tools`) use. **Passive** verifiers always run.
4. Run each verifier; write `verification_status`, `verified_at`,
   `extra["verification"]`.
5. **Idempotent** (overwrite the three fields, no append) → safe on DBOS replay.
   Runs **sequentially under the low-memory profile** and honours existing
   per-target rate limits (politeness).

A `Verdict` dataclass + `get_tool_verifiers()` are the only new engine surfaces;
DBOS/tooling stay behind their existing adapters.

---

## 7. Pipeline seam

In `_finalize_session`, insert verification **after the asset rollup, before the
issue rollup** — so the issue rollup mirrors `verification_status` onto `Issue` the
same way it already carries `severity`/`title`:

```
… → backfill_check_ids → asset rollup → [verify_session] → issue rollup
  → run_ai_post_scan → _dispatch_alerts → maybe_start_agent
```

Gated + fail-graceful, matching the sibling rollups:

```python
if getattr(settings, "FINDING_VERIFICATION_ENABLED", True):
    try:
        verify_session(session, threshold=settings.FINDING_VERIFICATION_MIN_SEVERITY)
    except Exception:
        logger.exception("[%s] verification failed — scan unaffected", session.id)
```

- **Subscans** keep skipping it (consistent with them skipping rollups/insights).
- **Invariant preserved:** with `FINDING_VERIFICATION_ENABLED=False`, finalize is
  byte-identical to today. The existing "AI-off ⇒ no AI traces" test is updated to
  hold verification constant (verification is a *separate* feature with its own
  toggle; the AI-gated part is only §8).

---

## 8. AI adjudication layer (optional, AI-gated)

Runs **only** when `guard.is_ai_active()`, inside `run_ai_post_scan` (after the issue
rollup). For each `verified`/`inconclusive` medium+ finding, an LLM re-examines the
stored evidence and writes `{confidence, rationale}` into
`extra["verification"]["ai"]`.

- **AI advises, deterministic decides** — it never changes `verification_status` and
  never touches `Finding.status` (preserves the AI invariants).
- Bounded by the existing `CLOUDFLARE_AI_MAX_CALLS_PER_SCAN` budget; one
  `AIInvocation` audit row per call (metadata only); fail-graceful.
- No-op when AI is off ⇒ the AI-off invariant holds.

---

## 9. Surfaces

- **API:**
  - `/api/findings/` + `/api/issues/` expose `verification_status`, `verified_at`,
    and the `verification` sub-dict.
  - `POST /api/scans/<uuid>/verify/` — re-run verification for a scan (auth-gated for
    active; `409` if the scan is still running).
  - `POST /api/findings/<id>/verify/` — re-verify a single finding on demand.
- **PDF report:** per-finding **Verified / Inconclusive / Unverified** badge + an
  **Evidence** line from the fresh re-probe (the "evidence/PoC" surface). The Issue
  Register gains a verified count. **Absent verification ⇒ report byte-unchanged.**
- **Frontend:** deferred (backend-first) — a verdict badge on finding rows + Scan
  Detail, wired in the final frontend pass.
- **Exposure score:** unchanged for v1 (no confidence-weighting — YAGNI).

---

## 10. Settings

| Setting | Default | Effect |
|---|---|---|
| `FINDING_VERIFICATION_ENABLED` | `True` | Master toggle for the finalize pass. `False` ⇒ finalize byte-identical to pre-verification. |
| `FINDING_VERIFICATION_MIN_SEVERITY` | `"medium"` | Lowest severity re-probed. |

Reuses the existing low-memory sequencing + per-target rate limits; no new
concurrency knobs.

---

## 11. Rollout / definition of done

1. Verification engine (`Verdict`, `verify_session`, auth gate) + registry
   (`get_tool_verifiers()`).
2. Model fields + two migrations; issue rollup mirrors `verification_status`.
3. Finalize seam behind `FINDING_VERIFICATION_ENABLED`.
4. **Seed verifiers** (§5) — `web_checker`, `tls_checker`, `ssh_checker`, `nuclei`,
   `nmap`.
5. API (finding/issue fields + the two verify endpoints).
6. Report badge + Evidence line.
7. Optional AI adjudication layer.
8. Docs: update `03-system.md` (new engine package + the finalize step) and
   CLAUDE.md; flip this spec's status to Implemented.

---

## 12. Design invariants (to be guarded by tests)

- `FINDING_VERIFICATION_ENABLED=False` ⇒ finalize byte-identical to pre-feature.
- A tool with no verifier ⇒ its findings stay `unverified` (never falsely verified).
- Active re-probe without `DomainAuthorization` ⇒ `inconclusive`, **no target
  contact**; passive verifiers always run.
- A verifier that raises ⇒ `inconclusive`, scan unaffected.
- `verify_session` is idempotent on re-run/replay.
- AI adjudication: no-op when AI off; annotates `extra` when on; **never** flips
  `verification_status` or touches `Finding.status`; audited; budget-bounded.
- Verdict mirrors onto `Issue` and persists across scans via the rollup.
