# WAF/Block Detection & Honest Coverage Contract — Design Spec

> **Status:** Draft for review. Execution belongs to a dedicated session, not the
> session that authored this. This document is the design contract; an
> implementation plan (`writing-plans`) should be derived from it before coding.

**Goal:** Stop OpenEASD silently reporting "nothing found" when a target's WAF
blocked, challenged, or rate-limited the scan. Detect interference, quantify it,
and report it as a first-class coverage statement — so an empty finding list
means "we looked and it's clean," never "we were blocked and didn't say so."

**Owner:** OpenEASD core. **Depends on:** nothing external. **Blocks:** the
credibility of every scan against a WAF-fronted target (i.e. most real customers).

---

## 1. Motivation — the problem is real and measured

Two confirmed facts as of 2026-08-16:

1. **No interference detection exists anywhere in the pipeline.** A grep across
   all tools for `waf | cloudflare | challenge | mitigated | 429 | 503 | captcha`
   turns up only SNI-routing code (making requests *arrive*) and unrelated auth
   403s. Nothing notices when a request is *rejected*.

2. **Measured impact:** scanning `cybersecify.com` (Cloudflare-fronted) from the
   OpenEASD droplet `64.227.164.62`, ~**48% of requests were mitigated** at the
   edge (65.75k of ~137k never reached origin). On a WAF target, roughly half of
   what the tool sends is blocked, and the report says nothing about it.

### How this degrades output, tool by tool
- **httpx** records a Cloudflare challenge as a *live* URL (200 "Just a moment…"
  or a 403) → downstream tools then scan the **challenge page, not the app**.
- **katana** crawls that challenge page → ~no real links → **under-counts** the
  web surface; the target looks small.
- **nuclei / web_checker** run templates and header checks against block/challenge
  responses → no matches → **"no vulnerabilities found"** presented as clean.
- **Rate-limiting compounds it:** nuclei runs at 100 req/s (`apps/nuclei/collector.py`
  `RATE_LIMIT = 100`), which can itself trip the target's limiter → later requests
  429 → more silent misses.

The failure mode is exactly: **"blocked" renders as "nothing found."**

---

## 2. Design principles (these constrain every decision below)

1. **Honesty over coverage.** The fix is to *report* interference, not to evade
   it. We do **not** rotate IPs, spoof browser identities, or slow-and-low to
   dodge a WAF. That contradicts the project's stated scope contract and OWASP
   Defender positioning.
2. **Don't "unblock the droplet."** Unblocking our own IP only fixes scanning our
   own sites; every real customer WAF still blocks us and we can't unblock those.
   The durable answer is detect + report + be identifiable so a customer can
   *deliberately* allowlist us when they want full coverage.
3. **Reuse signal we already collect** before adding new traffic. `URL.status_code`,
   `URL.title`, `URL.web_server` are already persisted per probe
   (`apps/core/web_assets/models.py`). Detection is post-processing first,
   new instrumentation only where the cheap signal runs out.
4. **No new finding noise.** Coverage is *not* a Finding. It is scan metadata
   surfaced alongside findings, so it can't be muted, dismissed, or double-counted.

---

## 3. Architecture — four components, phased

```
Phase 1 (cheap, high honesty value)
  C1  WAF/block detection      → classify each URL: reached | challenged | blocked | rate_limited
  C2  Coverage reporting       → per-target coverage summary on ScanSession + PDF section
  C3  Honest user agent        → OpenEASD/1.0 UA on httpx/katana/nuclei (enables allowlisting)

Phase 2 (harder, precise denominator)
  C4  Per-scan request counting → exact "blocked N of M" via a local counting proxy
```

Phase 1 delivers the core honesty win with no new network traffic. Phase 2 makes
the coverage number exact. Ship Phase 1 first; it stands alone.

---

## 4. Component C1 — WAF / block / challenge detection

**Where:** a new analyzer module, `apps/httpx/waf.py` (pure function, no DB), called
from `apps/httpx/analyzer.py` after URL rows are built. Runs over the httpx records
we already parse — no new tool, no new requests.

**Classification** per probed URL, from fields we already store:

| Class | Signature (any match) |
|---|---|
| `blocked` | status ∈ {403, 406, 429, 503} **and** `web_server` matches a WAF vendor (cloudflare, akamai, sucuri, incapsula, awselb, barracuda, f5) |
| `challenged` | `title` matches `just a moment` / `attention required` / `checking your browser` / `access denied` / `cf-chl` |
| `rate_limited` | status == 429 (any server) |
| `reached` | everything else (including a legitimate 404 — that's a real answer) |

**Vendor guess:** map `web_server` / known title strings → `waf_vendor`
(`"cloudflare"`, `"akamai"`, …). This is a **fingerprint guess from response
signatures**, never a claim about the target's configuration. When signatures are
present but don't match a known vendor, `waf_vendor = "unidentified"` and the report
says "WAF/edge, vendor unidentified". When there is no block/challenge signal at
all, `waf_vendor = null` and no coverage note prints.

**We report only what we observed** — that specific requests received block or
challenge responses — never *which rules* fired or *what* is allowed/blocked. That
config lives in the target's dashboard and we never assert it.

**New optional fields on `URL`** (`apps/core/web_assets/models.py`), all nullable so
existing rows are unaffected:
- `reachability = CharField(choices=[reached, challenged, blocked, rate_limited], blank=True)`
- (vendor lives at the target level, see C2 — not per URL)

**Non-goal for C1:** detecting blocking of *non-httpx* tools (nuclei getting 429s
mid-run). That needs the proxy (C4). C1 covers the probe layer, which is where the
challenge-page-masquerading-as-live-URL damage originates.

**Tests:** `tests/unit/test_waf_detection.py` — table-driven over synthetic httpx
records: a Cloudflare 403, a "Just a moment" 200, a plain 404 (must classify as
`reached`, not blocked), a 429, a clean 200. Assert no false positive on a real 404.

---

## 5. Component C2 — Coverage reporting

**Where:** compute at `_finalize_session` (`apps/core/scans/pipeline.py:89`), store on
`ScanSession` (`apps/core/scans/models.py`), surface in the scan-detail API and the
PDF report.

**New fields on `ScanSession`** (all default-safe):
- `waf_vendor = CharField(blank=True)` — fingerprint guess, else `"unidentified"` /
  `""` when no signal
- `endpoints_probed = IntegerField(default=0)` — count of httpx-probed endpoints
- `endpoints_blocked = IntegerField(default=0)` — probed endpoints that returned
  block / challenge / rate_limited

**Phase 1 reports an endpoint count, not a traffic percentage.** httpx does ~one
request per host, so all we can honestly state is *"N of M probed endpoints were
blocked or challenged."* We do **not** print a "% of requests" figure in Phase 1,
because the tool never counts nuclei's or katana's requests — that denominator
does not exist until C4. The traffic-weighted percentage ("blocked N of M
requests") is a **Phase 2** output, sourced from the proxy, and only then.

**Surfacing:**
- **API:** add the four fields + `reach_ratio` to the scan-detail schema
  (`apps/core/scans/api.py`). React scan-detail page shows a coverage banner when
  `probes_blocked > 0`.
- **PDF report** (`apps/core/reports/views.py` + `templates/reports/scan_report.html`):
  a new **"Scan Coverage"** block directly under the Executive Summary, only rendered
  when a WAF was detected:

  > **Scan Coverage — edge blocking observed.**
  > 12 of 41 probed endpoints returned block or challenge responses (fingerprint
  > suggests Cloudflare). Findings below reflect only reachable endpoints.
  > **Absence of findings on blocked surfaces is not evidence they are secure.**
  > To obtain full-coverage results, allowlist the scanner (`OpenEASD/1.0`, source
  > IP on file) in your WAF and re-run.

  Wording rules for this block (locked with the claims owner, 2026-08-16):
  - It states an **observation** (endpoints returned block/challenge responses),
    never a claim about the target's WAF configuration or rules.
  - Vendor is always hedged ("fingerprint suggests …"); degrades to
    "(WAF/edge, vendor unidentified)" when signatures don't match a known vendor.
  - **Phase 1 uses endpoint counts, never a "% of requests."** The traffic
    percentage is a Phase 2 (C4) output only.

  This paragraph is the honest scope contract. It is the single most important
  user-visible output of this whole spec.

**Tests:** extend `tests/unit/test_reports.py` — coverage block renders when
`waf_vendor` set and hidden when clean; `tests/integration/test_scan_flow.py` —
finalize populates the four counts.

---

## 6. Component C3 — Honest user agent (dependency of the allowlist story)

**Problem:** we pass **no** UA to httpx/katana/nuclei (confirmed: zero `-H` /
`-random-agent` in the collectors), so each binary emits its own default —
browser-like for httpx, a Chrome UA for headless katana, per-template UAs for
nuclei. That is the "rotating browser identities" seen in logs. It is *inherited*,
not deliberate, but it reads as evasion and it prevents a customer from
allowlisting us.

**Change:** add a setting `OPENEASD_USER_AGENT`
(default `"OpenEASD/1.0 (+https://cybersecify.com/openeasd)"`) and pass it explicitly:
- httpx: `-H "User-Agent: <ua>"` (`apps/httpx/collector.py`)
- katana: `-H "User-Agent: <ua>"` (`apps/katana/collector.py`)
- nuclei: `-H "User-Agent: <ua>"` (`apps/nuclei/collector.py`)
- historical_urls: gau/waybackurls hit archives, not the target — leave as-is.

**Honest caveat (must be documented, not hidden):** some nuclei templates hard-set
their own UA to trigger UA-specific checks; `-H` will not override those. So the
guarantee is "~all requests carry `OpenEASD/1.0`," not 100%. State this in the
README scope contract rather than overclaiming.

**Tests:** assert each collector's command vector contains the UA header
(extend `test_httpx.py`, `test_katana.py`, `test_nuclei.py`).

---

## 7. Component C4 — Per-scan request counting (Phase 2)

**Goal:** a true denominator — "blocked N of M requests" — universal across every
external tool, on every target, forever.

**The design fork (this is the decision the team must make):**

- **Option A — MITM counting proxy.** All tools route through a local proxy
  (`-proxy http://127.0.0.1:PORT` / `HTTP_PROXY`) that terminates TLS with an
  OpenEASD CA the container trusts. Sees every request's method/path/status →
  exact counts **and** exact block/reach classification for HTTP *and* HTTPS,
  universal across tools. **Cost:** CA cert provisioning in the image, tools
  configured to trust it, MITM complexity, some tool/cert edge cases.
- **Option B — CONNECT-tunnel proxy (no MITM).** Same proxy, but only counts
  connections and reads SNI/Host for HTTPS (can't see encrypted status). Gives an
  accurate *request/connection count* but block-vs-reach for HTTPS still leans on
  C1's httpx signal. **Cost:** low; no cert work.
- **Option C — per-tool stats parsing, no proxy.** Use nuclei `-stats-json`
  (emits request totals + errors) and httpx probe counts; katana/gau don't report,
  so coverage is partial and inconsistent. **Cost:** lowest; least accurate.

**Recommendation:** **Option B** for the count (accurate, no cert pain) combined
with **C1** for HTTPS block classification. Upgrade to **Option A** only if a
customer specifically needs exact per-request HTTPS block accounting. Do **not**
build A first — MITM is a large surface for a number most users will accept as
"~137k requests, ~48% blocked."

**Storage:** `ScanSession.requests_total`, `requests_blocked` (replace C2's
probe-based estimate once the proxy is live; keep the same report contract).

---

## 8. Non-goals / explicitly out of scope

- **No evasion.** No IP rotation, no browser-UA spoofing, no throttling-to-hide.
  If a WAF blocks us, we report it; we do not try to beat it.
- **No auto-allowlisting.** We never ask a customer to bypass their WAF for us
  silently; the coverage note tells them the trade-off and lets them choose.
- **No origin-IP discovery / WAF bypass techniques** (e.g. finding the real origin
  behind Cloudflare). That is offensive evasion and off-brand for a Defender tool.
- **Marketing-site / Cloudflare-dashboard work** (WAF rule authoring, support
  handoffs, zone analytics) — separate session, not this repo.

---

## 9. Suggested sequencing for the implementation plan

1. C3 (honest UA) — smallest, unlocks the allowlist story. ~1 collector change ×3 + tests.
2. C1 (detection analyzer) — pure function over existing httpx data + `URL.reachability`.
3. C2 (coverage on ScanSession + API + PDF "Scan Coverage" block) — the headline output.
4. C4 (counting proxy, Option B) — precise denominator, last.

Each of 1–3 is independently shippable and independently valuable. C4 is a distinct
follow-on and can wait.

---

## 10. Open decisions for the team

1. **C4 proxy: Option A (MITM) vs B (CONNECT-tunnel) vs C (stats parsing)?**
   Spec recommends B. Confirm before Phase 2.
2. **Coverage note wording** — the paragraph in §5 is the scope contract; it should
   be reviewed by whoever owns the public claims (no overclaim, no "we guarantee").
3. **Should `reachability` also gate downstream tools?** e.g. skip nuclei on URLs
   classified `challenged` (scanning a challenge page is wasted budget). Proposed:
   yes, but as a *follow-up* — Phase 1 only detects and reports; it does not change
   what gets scanned, to keep the change reviewable.
