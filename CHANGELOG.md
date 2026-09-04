# Changelog

All notable changes to OpenEASD are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) with a short
**Why** note on non-obvious changes so reviewers don't have to dig through
commits to recover the reasoning.

## [Unreleased]

### Changed
- **Third-party licensing hygiene (attribution + notices).** Added a
  `THIRD_PARTY_NOTICES.md` covering every bundled binary and data source: MIT
  notices (ProjectDiscovery ×7, nuclei-templates, gitleaks, gau, cloud_enum),
  the **Apache-2.0 NOTICE for amass** (was missing), a **GPL-2.0 source offer for
  subzy**, the **NPSL "uses Nmap Security Scanner" notice**, and EPSS/CISA-KEV/
  Hudson-Rock/Shodan data-source attributions. Added the EPSS + KEV + Hudson Rock
  citation to the PDF report's Methodology section. **Why:** the Docker image
  redistributes these binaries, so their licenses require the notices; this closes
  the gap flagged by a dependency licence/ToS audit. No license purchase is
  required for OpenEASD's free/non-commercial use.
- **Documented Shodan InternetDB's non-commercial restriction** (settings +
  notices): a *paid* product built on OpenEASD must supply its own Shodan key
  rather than rely on the free keyless InternetDB tier.

### Removed
- **Dropped `waybackurls`** from the historical-URL collector and the Docker image.
  It ships without a declared license (redistribution-ambiguous), and `gau` — which
  we already run — is a strict superset of its one source (the Wayback Machine),
  also covering Common Crawl, AlienVault OTX, and URLScan. Zero coverage loss.

### Added
- **GitHub public-secret tool (`apps/github_secrets`) — tool #24.** Searches
  **public GitHub** for the target org's leaked secrets: confirms the org via
  `GET /orgs/{org}`, runs org-scoped `GET /search/code` queries (`.env`,
  `.npmrc`, `credentials`, `id_rsa`, `.pem`, and an `org:{org} "{domain}"` string
  search), fetches the matching blobs (capped by count + bytes), and runs
  **gitleaks** over them — the same detection engine `js_secrets` points at
  fetched JavaScript, aimed here at the org's public GitHub footprint. Findings
  share `check_type="exposed_secret"` with js_secrets so both secret sources
  group together in the report. **Passive** (`active=False`): every request goes
  to GitHub's own API, **never to the target** — no `DomainAuthorization`. In
  default Full Scan + Passive Scan (migration `0026`). 32 tests.
  - **BYOK is mandatory** (`GITHUB_TOKEN`): GitHub's code-search API requires
    auth, so with no token the tool is a **logged no-op** — a keyless Full Scan
    is never broken. `GITHUB_ORG` pins the org (recommended; auto-derivation from
    the domain apex label is best-effort and flagged lower-confidence).
    `GITHUB_SECRETS_GLOBAL_SEARCH` (default off) enables an extra noisy un-scoped
    bare-string search; default is **org-scoped only**.
  - **Redaction is enforced** (reused verbatim from js_secrets): only a redacted
    `secret_preview` + scrubbed `match_preview` are stored — the full secret
    never lands in the DB or report (asserted at the DB level in tests).
  - **Fail-graceful + bounded:** any GitHub API timeout / non-200 / exhausted
    rate-limit (429, 403 + zero remaining, secondary limit) / JSON error is
    logged and skipped, never raised (only a missing/timed-out gitleaks binary
    raises, like js_secrets); GitHub rate limits are honoured with capped backoff
    (`Retry-After` / `X-RateLimit-Reset`); queries, files, and bytes are all
    capped per session.

  **Why:** credentials committed to public GitHub are one of the most common and
  most damaging real-world leaks, and they are harvested by automated scanners
  within minutes of a push — this surfaces them in the same passive, no-auth
  recon pass that already runs before any target contact, closing a gap that the
  on-site `js_secrets` (which only sees the target's own served JS) cannot cover.
  **Key never ships in the image** (that would leak the token + spend the
  operator's own GitHub quota + breach GitHub's API ToS): the token is a
  per-deployment secret and the operator uses their own quota. Uses GitHub's
  official API only and honours its rate limits.
- **Data-breach exposure tool (`apps/breach_check`) — tool #24.** A passive,
  Phase-1 (Domain Intelligence) tool that reports which of the org's accounts /
  how many known breaches are tied to the target domain, using third-party breach
  datasets. Sends **no packet to the target** (`active=False`, no
  `DomainAuthorization`) and joins both the default **Full Scan** and the no-auth
  **Passive Scan**. Two-tier, bring-your-own-key:
  - **Free tier (default, zero config):** **XposedOrNot** public breach catalog
    (`GET /v1/breaches?domain=<domain>`) — keyless, no credits. Returns the known
    breaches whose breached organisation matches the domain (breach name, year,
    record total). Every Docker deployment gets it.
  - **Authoritative tier:** set `HIBP_API_KEY` → **Have I Been Pwned**
    `GET /api/v3/breacheddomain/<domain>` (requires the operator's paid HIBP
    subscription **and** HIBP-verified domain ownership; honest `user-agent` +
    `hibp-api-key` headers sent). Yields the number of affected accounts + the set
    of breach names.

  Emits **one aggregate Finding** (`check_type="breach_exposure"`, CWE-359) when
  exposure is found — `high` severity on a large affected-account count (≥100) or
  a breach within the last 3 years (reused credentials are a live
  credential-stuffing risk), else `medium`; no exposure → no Finding. Fail-graceful
  throughout (timeout / 500 / exhausted 429 / bad-JSON / HIBP 404·403 never raise;
  429/Retry-After honoured with capped backoff).
  **PRIVACY (hard requirement, mirrors `hudson_rock`):** only aggregate COUNTS +
  PUBLIC breach metadata (names/years/record totals) are ever stored. The HIBP
  response is keyed by email alias (PII); the collector reads only the alias
  *count* and the breach-name union and **discards the alias keys** — no email
  address or credential ever reaches a Finding. Enforced by
  `test_breach_check.py` at the collector, analyzer, and end-to-end layers.
  **Why:** breach exposure is a high-value external signal a defender can act on
  immediately (force resets, MFA, block breached passwords) yet most EASD tools
  omit it; shipping a free keyless source out of the box means it always adds
  value, while HIBP BYO-key gives operators the authoritative per-account data
  when they have it. `HIBP_API_KEY` is a per-deployment secret, never baked into
  the public image.
- **Lookalike / typosquat domain tool (`apps/typosquat`) — tool #24.** Generates
  lookalike candidates for the apex domain algorithmically — homoglyph, adjacent-key
  substitution/insertion, omission, repetition, transposition, hyphenation, and
  common-TLD swaps (capped at `MAX_CANDIDATES=300`, truncation logged, never silent)
  — then checks which are **registered / weaponizable** via public DNS. A candidate
  with A/MX records (can serve a phishing page or receive mail) is `medium`; one with
  only NS (registered/parked) is `low`. One Finding per registered lookalike
  (`check_type="lookalike_domain"`, CWE-451 UI Misrepresentation), with the technique,
  DNS records, and resolved IPs in `extra`. Passive (`active=False`, no
  `DomainAuthorization`, no API key) — every DNS query targets the CANDIDATE domain's
  public DNS; **the target is never contacted**. Fail-graceful: any resolver
  error / timeout / NXDOMAIN is treated as "not registered" and skipped; the tool
  never raises and never fails a scan. In default Full Scan + Passive Scan (migration
  `0026`). 29 tests.

  **Why:** lookalike domains are the *threat surface* a defender doesn't see from
  their own assets — phishing infrastructure and brand abuse are stood up on
  confusable domains (`examp1e.com`, `example-support.com`, `example.io`) that never
  appear in the org's DNS or CT logs. Surfacing which confusable names are already
  *registered and live* is a high-signal, zero-cost addition to the passive report:
  it needs no key, no authorization, and no packet to the target, yet it names
  concrete attacker-controlled infrastructure — a strong free-report hook and a
  natural upsell signal (continuous lookalike monitoring / takedown). It runs in the
  no-auth **Passive Scan** mode, so a prospect gets it before granting authorization.
- **Exposure Score + trend — one 0–100 executive risk number per scan.** Each
  completed scan now gets a single saturating, severity-weighted score
  (`raw = 25*critical + 8*high + 2*medium + 0.5*low`, capped at 100; `info`
  contributes 0) plus a letter grade (A best … F worst; bands 0–19 A, 20–39 B,
  40–59 C, 60–79 D, 80–100 F). A clean scan scores 0 / grade A. The score and
  grade are stored per scan on `ScanSummary` (migration
  `insights.0002`), so trend is queryable, and the delta vs the same domain's
  previous scan (up = worse / down = better / flat) is computed Python-side to
  avoid the SQLite JSON-aggregation quirk. Surfaced in `GET /api/insights/`
  (per-scan `exposure_score`/`exposure_grade` on each `scan_trend` entry, plus a
  top-level `exposure` object with the latest domain's score, grade, and trend),
  in `GET /api/dashboard/` (per-domain `exposure_score`/`exposure_grade` on each
  `domain_status` row), and as an "Exposure Score" block in the PDF report.
  **Why:** the finding list lands with an engineer but not with the non-technical
  buyer who signs off; a single number that trends over time gives that reader
  something to track and anchors the free→paid value story (you improved your
  score, here's how to keep improving it). Weights are named module constants in
  `apps/core/insights/scoring.py` so the curve stays tunable. Frontend rendering
  of the score/trend is deferred (backend + report only for now).
- **Shodan passive exposure tool (`apps/shodan`) — tool #23.** Reads Shodan's own
  internet-wide scan dataset for each resolved public IP and reports exposed
  ports/services + known CVEs, **without sending a packet to the target**
  (passive, `active=False`, no `DomainAuthorization`). Two-tier, bring-your-own-key:
  - **Free tier (default, zero config):** Shodan **InternetDB** — ports, CPEs,
    CVE ids per IP. No key, no credits. Every Docker deployment gets it.
  - **Enhanced tier:** set `SHODAN_API_KEY` → full host API (service banners +
    versions + tags). `SHODAN_MAX_IPS` (default 50) caps the paid path's queries
    to protect plan credits; the free path is uncapped (costs nothing).

  **Why:** completes the "what's already publicly visible about you" picture that
  the passive report is built on — Shodan shows exposure from an external vantage
  that active tools (nmap) can't reach when a target blocks or rate-limits our
  scanner, and it runs in the no-auth **Passive Scan** mode where nmap cannot.
  **Not a duplicate of nmap:** different *method* (passive/external vs
  active/first-hand) covering a different failure mode. CVE ids are stored in
  `extra["cve_ids"]` so the existing `cve_intel` phase enriches them with EPSS +
  CISA KEV — a Shodan-surfaced KEV CVE is exactly the "worth a pentest" signal.
  **Key never ships in the image** (that would leak it + breach Shodan's ToS): the
  key is a per-deployment secret; keyless users get the free tier. In default Full
  Scan + Passive Scan (migration `0025`). 20 tests.

### Changed
- **Tools now run to completion and deliver full output — no output caps.** The
  product's value is complete results in one UI, so instead of *capping* tools to
  fit the small box we give them the TIME to finish (the scan window is 48h and
  the freeze is fixed, so the box stays responsive during a long run):
  - **Removed the nuclei URL cap** (default `NUCLEI_MAX_TARGETS=0`) — nuclei scans
    the whole discovered surface, not a truncated subset. (A deployment can still
    opt into a cap; it's then logged, never silent.)
  - **nuclei wall-clock 2h → 6h** (`NUCLEI_TIMEOUT`), **worker hard-kill 4h → 24h**
    (`Q_TASK_TIMEOUT`), **stuck-scan watchdog 4h → 24h** — so a large scan finishes
    instead of being killed mid-run.
  - **amass delivers its partial subdomains on a time-limit** instead of
    discarding them and failing the scan — a time-boxed enumeration run is a
    normal, worthwhile result (like subfinder), and it's logged.
  - **nuclei + nuclei_network deliver the findings they already wrote when the
    wall-clock still hits** instead of raising and reporting a false 0. The
    hardened runner (`run_capped`) already captured the partial stdout on
    `TimeoutExpired.output`; the collectors now parse and return it. **Why:** on a
    very large surface even the 6h budget can be exceeded — dropping tens of real
    findings because the run was one template short of done is exactly the
    "results, not challenges" failure the uncap set out to fix. The truncation is
    logged, so it's visible, never silent.
  - **All profiles now include `low` severity** in nuclei (only `info` tech-detect
    noise, already covered by httpx, is dropped) — more findings, not fewer.

### Fixed
- **Subdomain count no longer inflated by dead alterx guesses.** alterx generates
  permutation *candidates* (dev-api.…, api-staging.…); those that don't resolve
  were stored and counted as real subdomains — a cybersecify.com run showed
  "1,862 subdomains" for a **5-subdomain** surface (1,857 dead alterx candidates).
  dnsx now prunes unresolved alterx candidates after resolution, so the count
  reflects the real, live surface. Discovery-tool names (subfinder/amass) are kept
  even when unresolved — those are real observed names, not guesses.
- **Two issues the live cybersecify.com validation run exposed.** (1) A **passive
  scan spuriously emitted a `scan_coverage` "results incomplete" finding** because
  the coverage-regression check diffed it against a prior *active* (Full Scan)
  baseline — a passive scan runs far fewer tools, so it always looked like a
  collapse. The check now only compares scans of the **same workflow**. (2)
  **nuclei hit its 2h wall on a large surface** (a Full Scan fed it 368 URLs);
  its target list is now **capped per profile** (`NUCLEI_MAX_TARGETS`; low=100),
  live-probed (httpx) URLs first, cap logged (never silent).
- **CI runs on every PR** (dropped the `pull_request` `paths-ignore`): now that CI
  is a required status check, a docs-only PR would otherwise never trigger it and
  be unmergeable. The `push` `paths-ignore` still skips the image republish on
  docs-only merges.

### Changed
- **nuclei hardening (follow-up to the severity scoping).** Three parallel agents
  investigated nuclei's freeze/timeout/value; key finding: `-severity` does NOT
  cut the ~500 MB startup template parse (nuclei parses all templates then
  filters) — it only fixes the TIMEOUT. So the FREEZE is now bounded by
  `GOMEMLIMIT` **+ `-bulk-size`** scaled per profile (low=5) — the real
  peak-memory lever, previously left at the default 25. Also: `-type http` on the
  web run (skips dns/tcp/ssl already covered by nuclei_network/tls_checker),
  `-max-host-error` (abandon dead hosts), `-exclude-tags dos,fuzzing,intrusive`,
  and stderr surfaced regardless of exit code. **Fixed:** `nuclei_network` used a
  plain `subprocess.run` with no process-group kill — the exact worker-wedging
  hang the web collector was rewritten to avoid; both now share `run_capped`
  (`apps/core/workflows/proc.py`). Added a **weekly CI cron** so baked
  nuclei-templates refresh on cadence. Learnings + the corrected freeze
  attribution recorded in `docs/SCAN_OPERATIONAL_LEARNINGS.md`.

### Added
- **Configurable support channel for the in-app "Report an issue" / "Request a
  feature" links** (`SUPPORT_EMAIL` env). When set, the footer buttons become
  `mailto:` links to that address with the running build pre-filled in the body
  (a branded deployment routes users to its own support inbox); when empty (OSS
  default) they fall back to filing a GitHub issue. Surfaced via
  `GET /api/version/` (`support_email`).

### Changed
- **nuclei template severity scoping — the fix for its freeze/timeout/noise.**
  nuclei compiles its entire ~13,500-template set into RAM at startup regardless
  of target count, which (1) swaps a small host into a multi-minute freeze and
  (2) makes the run hit its wall-clock cap. `info` templates are ~38% of the set
  and `low` ~4%, and `info` is mostly recon noise already covered by httpx
  tech-detect + web_checker. So the scan now runs `-severity` scoped per resource
  profile: `low` → `critical,high,medium`; `balanced`/`high` → `+low`; `info`
  dropped everywhere. Overridable via `NUCLEI_SEVERITY`. Cuts template-load
  memory **and** request volume, raising signal. Combined with the existing
  low-profile `GOMEMLIMIT` cap, this is what lets nuclei complete on a 1 GB box.
  **Learning captured in** `docs/SCAN_OPERATIONAL_LEARNINGS.md` with regression
  tests, per the standing "operational issues become tests" rule.

### Fixed
- **Live defects found by a full test-suite audit (silent-failure class).** A
  7-agent audit of the ~45-file suite found real bugs the 1200+ tests missed
  because they were shallow on failure modes (and, in two cases, actively
  codified the bug):
  - **amass swallowed its own timeout** and returned partial results with no
    error, so a hung amass made the whole scan read `completed` with a truncated
    surface. Now raises `ToolTimeout` (→ scan `partial`). The test that asserted
    the swallow was rewritten to assert the raise.
  - **takeover_check silently dropped `vulnerable:True` records** whose service
    it couldn't fingerprint — so any drift in subzy's output fields would make
    every real subdomain takeover vanish. Now reports them with an "unidentified
    service" label. The test that blessed the drop was inverted.
  - **nmap returned a falsely-clean CVE result when every target IP timed out**
    (per-IP timeouts are still skipped as degraded, but an all-IP timeout now
    raises `ToolTimeout`).
  - **The coverage note claimed endpoints "returned block or challenge
    responses" even for silent drops** that returned nothing; wording now
    distinguishes a real WAF block-page from a no-response/non-HTTP endpoint.
  - **domain_security aborted the entire RDAP check** (`KeyError`) on a real
    registrar event missing `eventAction`; now guarded.
  - **alterx** no longer silently returns nothing when its binary is missing —
    it raises `ToolBinaryMissing` like every other tool (dead unreachable branch
    removed).
  - **nuclei / nuclei_network crashed on `info: null`** — `data.get("info", {})`
    returns `None` when the key is present with a null value, then `.get()` on it
    raised `AttributeError` and lost the finding. Now `data.get("info") or {}`.
  - **katana crashed on a non-dict `request` or null `endpoint`** in crawl output.
    Both are now guarded. (All three surfaced by new adversarial parser tests.)
- **Silent scan degradation is now surfaced, not hidden.** Three linked fixes so a
  scan that was blocked/incomplete stops reading as a clean, complete scan (found
  after the droplet's results quietly dropped from ~50 findings to ~18 when the
  target began dropping its probes, only noticed by manually comparing reports):
  - **Scan status reflects the workflow outcome.** `_finalize_session` no longer
    hard-codes `completed`; if any tool failed or timed out (run is `partial`),
    the scan is marked **`partial`**. Previously a half-finished scan (e.g. nuclei
    timing out) still showed `completed`.
  - **Silent blocks are counted.** httpx records how many endpoints it was asked
    to probe (`endpoints_probed`); coverage now treats every probed endpoint that
    did not come back cleanly as blocked/unreachable — so "probed 100, 0 came
    back" (a silent IP drop that leaves no URL to classify) is visible instead of
    looking like a clean site. **Why:** the prior logic only classified URLs httpx
    *returned*, so a total block (zero URLs) read as `probed=0, blocked=0`.
  - **Coverage-regression warning.** A scan that surfaces far less than the
    previous one for the same domain (findings or live web endpoints halved, or
    ≥80% of probes unreachable) now emits an in-report `scan_coverage` finding
    telling the operator the results are a lower bound and the scanner may be
    blocked — instead of them having to diff two reports by eye.
- **Provenance endpoints (`/api/version/`, `/health/`) now send `Cache-Control:
  no-store`.** **Why:** Cloudflare (and any CDN) was caching the unauthenticated
  `/api/version/`, so the in-app build line showed a stale version/sha for hours
  after a redeploy. No-store keeps the displayed build honest on every deploy.

### Changed
- **nuclei / nuclei_network now honour a Go soft memory limit in the `low`
  profile** (`NUCLEI_GOMEMLIMIT`, default `600MiB`; `GOGC=50`). **Why:** nuclei
  loads its whole template set into RAM (the real footprint — independent of the
  polite request-rate cap), which on a 1 GB host swaps hard and can freeze the
  whole box, including the web UI, for minutes. `GOMEMLIMIT` makes the Go runtime
  GC aggressively near the ceiling, holding RSS down while keeping full template
  coverage. Unset (unbounded, prior behaviour) on the balanced/high profiles.

### Added
- **In-app version footer + "update available" check for logged-in users.** The
  build provenance line (`OpenEASD vX.Y.Z · <sha> · <date>`) and the
  Report-an-issue / Request-a-feature links now render in the sidebar of every
  authenticated page, not only on the login screen. A new authenticated endpoint
  `GET /api/version/latest/` compares the running build against the latest public
  GitHub release (cached 6h, fully fail-graceful) and the footer shows an "↑
  Update available: vX.Y.Z" link when the deployment is behind. **Why:** an
  operator using the app never saw which version they were running or how to
  report a problem — both were hidden pre-login — and had no signal that a newer
  release existed. The app still never self-updates; this is a heads-up + link,
  so upgrades stay an explicit redeploy.
- **Infostealer-exposure tool (Hudson Rock)** — a new passive Domain-Intelligence
  tool that surfaces a domain's infostealer-log exposure via Hudson Rock's free,
  keyless Cavalier API (aggregate counts, stealer families, last-seen dates, and
  system-level affected login URLs). **Why:** stolen-credential exposure from
  info-stealer malware is a leading breach vector that no port/web scan can see;
  it is public-source (passive) intel that complements the active surface scan.
  OSS use permitted by Hudson Rock co-founder Alon Gal. Privacy: only aggregate
  counts are stored — the tool never persists or displays plaintext credentials
  or individual email addresses, and it is fail-graceful so it can never fail a
  scan. Added to the Full Scan and Passive Scan workflows (tool count 21 → 22).
- **Passive vs active scan modes** (#251). A "Passive Scan" workflow uses only
  public-source tools and needs no `DomainAuthorization`; any active tool keeps
  the gate. **Why:** lets you scan an inbound inquiry from public data alone
  without authorization, while active probing stays gated. `domain_security` is
  classified active (it does AXFR/SMTP/mta-sts probes, not just DNS lookups).
- **ASN/IP-range discovery** tool via `amass intel` (#245) — finds org-owned
  CIDRs with no DNS record. Reports ranges only; does not auto-expand scanning.
- **gitleaks JS-secret scanning** (#248) — hardcoded keys in crawled JavaScript
  that nuclei's path-based templates miss. Secrets are redacted, never stored.
- **Technology fingerprinting** via httpx `-tech-detect` (#247).
- **DNSSEC chain-of-trust, MTA-STS, and open-relay checks** in domain_security
  (#244). Open-relay probe is safe — it never sends message data.
- **Report: "Fix First" priority block + EPSS/KEV** (#243) and **headline risk,
  plain-language business impact, and honest snapshot framing** (#250). **Why:**
  make the report read like a prioritised analyst review, not a flat dump.
- **WAF/edge coverage reporting + honest `OpenEASD/1.0` user agent**. **Why:** an
  empty result should mean "clean", never "silently blocked", and a target can
  deliberately allowlist the scanner.
- **Scheduled security-bump workflow** (#239) — keeps the lockfile ahead of the
  CVE feed so pip-audit stops failing unrelated PRs.

### Changed
- **Full Scan is the default workflow again** (#236), applied to existing DBs.
- **D-004 (Brand Protection product boundary) retired** (#246) — Brand Protection
  is no longer a separate product; capabilities are judged on free + in-scope + value.

### Fixed
- False positives: CDN edge IPs excluded from port/TLS scans (#237); out-of-scope
  URLs and cross-domain crawl dropped (#241, #249); TLS SNI uses hostname not IP
  (#241); takeover skipped on unknown service, alterx skipped on wildcard DNS (#242).
- PDF endpoint OOM cap at 50/finding — fixes a gunicorn OOM on very large scans (#238).
- Removed hardcoded `.bank.in`/RBI text from the DNSSEC finding — now framework-neutral (#249).

## [v0.10.0] — 2026-08-03

### Added

- **Self-serve add-and-scan-once from the Start Scan page.**
  - **What:** `/scans/start` is a single flow — one domain field (type a new or
    existing domain, with autocomplete), one "I have authority to scan this domain"
    attestation checkbox, one **Start Scan Now** button. Submitting creates the
    domain if new, authorizes it via a new `POST /api/domains/{pk}/authorize/`
    endpoint (records a `DomainAuthorization` — auth_type `owner`, the logged-in
    user, today's date), and starts the scan. No Django admin, no separate
    add/authorize steps. The Domains-page **Scan** button routes into the same
    form for any domain (no longer dead-ends at "authorize in Django admin").
  - **Why:** Authorization could previously be granted only through Django admin, so
    the intended "add a domain and scan it" flow could not be completed in the UI.
  - **Hypothesis:** (user-driven) operators need to scan newly-supplied domains on
    demand without an admin round-trip; a lightweight on-the-record attestation keeps
    the consent gate for the public Docker build while removing the admin friction.
  - **Evidence:** (user-driven) reported directly — "I want to add domains and scan
    them once via UI; it's not happening." The gate is deliberately retained because
    the same image ships as the public GitHub Docker download, where it is the user's
    responsibility to confirm they have authority.
  - Does not touch the scheduler or `SCHEDULED_SCANS_ENABLED`; automatic scanning
    remains disabled on the managed deployment.

### Housekeeping

- **Docs drift + version sync** — Rebuilt the CLAUDE.md test-count table against the actual suite (dropped two removed files, added 13 missing ones, corrected stale counts → **970 tests, 929 fast + 41 slow**), added the undocumented API routes (`/api/notifications/*`, `domains/<pk>/monitoring/`, `scans/<uuid>/subscan/`, `scans/urls/`, `workflows/<pk>/rename/`), reverted `pyproject.toml` `1.0.0` → `0.9.0` to match the latest tag + CHANGELOG (it had been bumped ahead of a release that hasn't been cut), and gitignored `.DS_Store`. **Why:** a claims-trace audit found the counts and endpoint list had drifted from the code; keeping the version ahead of the tag invites shipping a mislabelled build.

### Changed

- **PDF report engine switched from xhtml2pdf to WeasyPrint.** WeasyPrint renders full CSS — full-bleed dark cover, first-page-different (`@page:first`), running header/footer via `@page` margin boxes, rounded corners — which xhtml2pdf structurally cannot do. The report now renders as a true dark-cover assessment document. Rendering is isolated behind `_render_pdf()` so tests mock it without importing WeasyPrint or needing its system libraries; the Dockerfile and CI add the `pango` / `gdk-pixbuf` runtime libs (cairo was already present). Dependency: `xhtml2pdf` → `weasyprint`.

- **PDF report rebuilt to a professional assessment structure.** The export now produces a light-themed, sectioned report: dark cover, running footer with page numbers, **Document Control** table, **Executive Summary** with a computed Overall Risk Rating + severity distribution + asset discovery, a **Findings Summary** table (finding IDs `OE-YYYY-NNN`, Scope, Severity, CVSS, Hosts, Status), **Detailed Findings** grouped into severity sections with per-finding cards (severity bar, CVSS, CWE category, source/check, CVE list, affected-endpoint list, description, evidence, remediation), and a **Disclaimer**. Scope is mapped from source/check_type, CWE from a per-check map, and CVSS is the finding's measured score (CVE findings) or a severity-band default. All content is derived from scan data — no analyst/LLM narrative. Builds on the finding-grouping change below.

- **PDF report groups repeated findings and fits the cover to one page.** Tools raise the same issue once per affected target — e.g. 20 "Unencrypted HTTPS" findings differing only by IP:port — and the report previously rendered a full description/remediation card for every instance, so ~25 of 34 findings on a typical scan were near-identical boilerplate. The report now collapses findings that share the same issue identity (severity, source, check_type, and normalized heading — matching across targets even when each finding's description embeds per-target text) into one block with a compact **Affected Targets** table beneath, and the Findings Overview lists one row per issue type with a target count. No information is lost — every target is still listed, once per issue instead of once per instance — and report length drops sharply (a 40-finding scan renders as 5 issue blocks). The cover was also rebuilt as a single-cell table so its dark panel renders as one continuous page (xhtml2pdf bands a `<div>` background per child block) and tightened to fit on one page instead of two.

### Fixed

- **PDF report severity summary counted 1 per severity instead of the real totals.** The Executive Summary strip (and the "Total Findings" number) showed `1` for every severity that had any findings and `0` for the rest — so a scan with 4 critical / 14 high / 54 info rendered as `1 / 1 / … / total 5`, even though the findings *table* below listed all of them correctly. **Root cause:** the `findings` queryset is ordered by `(severity, -discovered_at)`, and that trailing `discovered_at` leaked into the `GROUP BY` of the per-severity `Count("id")` (a Django ORM gotcha), so each bucket grouped by `(severity, timestamp)` → one row per finding, each counted as 1, and the overwrite loop left every bucket at 1. `total_findings` (sum of those) then equalled the number of non-empty severities. Fix: reset the ordering with `.order_by()` before `.values("severity").annotate(...)`. **Why it slipped through:** the report test fixtures only ever created one finding per severity, where the broken count (1) coincidentally equals the right answer. Regression test now uses multiple findings per severity. **Evidence:** user-reported — two real PDF reports showed the mismatch (a 12-finding scan summarised as "4", a 72-finding scan as "5").

- **`click` 8.3.2 → 8.4.2 and `pillow` 12.2.0 → 12.3.0** — clears freshly-disclosed advisories PYSEC-2026-2132 (click) and PYSEC-2026-2253…2257 (pillow), which pip-audit flags on every CI run against the old pins. Transitive deps; lockfile-only bump, no behavior change.

- **`kubectl apply -k k8s/` can no longer take the site offline by clobbering `ALLOWED_HOSTS`** — The committed `configmap.yaml` held the deployment's real serving hostname in `ALLOWED_HOSTS`/`CSRF_TRUSTED_ORIGINS`. Two problems: it leaked a private hostname into the public repo, and because the configmap is part of the kustomize base, running the documented `kubectl apply -k k8s/` deploy step would overwrite the live host with whatever the file said — so scrubbing it to a placeholder turned a routine re-apply into an outage (Django `400`s every request whose `Host` isn't in `ALLOWED_HOSTS`). Fix: move the real `ALLOWED_HOSTS`/`CSRF_TRUSTED_ORIGINS` into `openeasd-secret`, which is applied out-of-band and is deliberately **not** listed in `kustomization.yaml`, so `apply -k` never touches it. `configmap.yaml` now carries placeholders only, and the deployment's `envFrom` already lists `secretRef` after `configMapRef` (last source wins), so the secret's values override the placeholders at runtime. **Why:** the deploy path documented in CLAUDE.md must be safe to run at any time; a config re-apply should never be able to knock the live host offline, and the real hostname should never be in the repo. **Evidence:** verified against the live cluster — the rendered `kubectl kustomize k8s/` output manages only configmap/service/pvc/deployment (no Secret), the secret now durably holds the real host, and the deployment `envFrom` order makes the secret win over the configmap placeholder.

### Security

- **Unattended scans now require domain authorization, and a master switch can disable them entirely.** Two changes close a consent gap in the scheduler: (1) `daily_scan` and per-domain monitoring now scan only domains that carry a `DomainAuthorization` record (`authorization__isnull=False`), and `run_monitoring_scan` re-checks authorization at run time; (2) a new `SCHEDULED_SCANS_ENABLED` setting (default `True`) gates whether the auto-scan schedules are registered at all — when `False`, `setup_core_schedules()` registers only the hygiene jobs (stuck-scan watchdog, token purge) and actively removes any `daily_scan`/`monitor_*` schedules a prior boot created. The k8s configmap sets it `False` so the managed deployment is manual-only. Manual/API scans are unaffected (they already gate on authorization at the view layer). **Why:** the manual entry points (scan-start API + the UI domain dropdown, which filters on `is_active && authorization`) already refused unauthorized domains, but `daily_scan` looped *every* active domain and called `create_scan_session` directly — bypassing the gate. An active-but-unauthorized domain would therefore be auto-scanned nightly with no consent check. Separately, `setup_core_schedules()` re-creates the `daily_scan` schedule on every qcluster startup with no way to opt out, so deleting it never stuck — during a restart storm it reappeared every boot. **Hypothesis:** gating on the authorization record (the same signal the UI/API already trust) is the right consent primitive, and a registration-time switch is what makes "manual-only" durable across restarts. **Evidence:** user-driven — a managed instance was observed with an active, unauthorized domain and an armed `daily_scan` scheduled to fire, after the operator had deliberately cleared scan data to prevent exactly that. 12 new/updated scheduler + monitoring tests.

## [v0.9.0] — 2026-07-12

### Added

- **Cybersecify branding on the README and PDF report** — Company logo added to the README header (brand SVG) and the PDF report cover (white variant, sized for the dark `#0d1117` cover), embedded as a base64 data-URI so the PDF engine (xhtml2pdf/pisa) needs no `link_callback` or static-file resolution. **Why:** brings the repo's public copy and the customer-facing report in line with the `cybersecify.com` brand; the report previously carried no company logo.

- **CVE Intel tool (`apps/cve_intel`)** — New Phase 12 tool in a new *Prioritization* phase group that enriches existing CVE findings in place with **EPSS** scores (FIRST.org exploitation-probability) and **CISA KEV** flags (known-exploited-in-the-wild), rather than producing new findings (`produces_findings=False`). Reads every session Finding carrying a CVE (both shapes tools write — nmap's `extra["cve"]` string and nuclei's `extra["cve_ids"]` list), runs one CISA KEV lookup (cached 24h) plus one bulk EPSS query, and writes a per-finding rollup back into `extra`: `epss_score`/`epss_percentile` (the max across the finding's CVEs), `cisa_kev` (true if any is actively exploited), `kev_cves`, and a per-CVE `cve_intel` map. Both feeds degrade to empty on any network/parse failure, so a scan never fails because a feed is down. 24 unit tests. **Why:** a scan that returns 55–157 findings is only useful if the operator knows which 3 to fix first. EPSS answers "how likely is this to be exploited" and KEV answers "is it being exploited right now" — together they turn a flat wall of CVEs into a ranked, actionable list. This is the single highest value-per-effort add for the defender audience, and it costs no scan time (pure enrichment on findings that already exist). **Hypothesis:** on a typical infra-heavy target, a small number of the CVE findings will carry a KEV flag or high EPSS, and surfacing those first is what a defender actually acts on. **Evidence:** user-driven — requested directly during the reference-target investigation after a partial scan produced dozens of undifferentiated CVE findings. Resolves [#159](https://github.com/cybersecify/OpenEASD/issues/159) via [#160](https://github.com/cybersecify/OpenEASD/pull/160). Follow-up (not in this change): surfacing EPSS/KEV in the findings table and PDF report with sort/filter.

- **Frontend data layer migration** — Data fetching moved to React Query + axios (#132) and routing to react-router-dom v7 (#129), replacing the hand-rolled `useFetch`/`usePolling` hooks and the popstate router. **Why:** cache invalidation, request dedup, and background refetch were being reimplemented by hand; standard libraries remove that surface area and the associated unmount-leak / refetch-race bug class.

### Fixed

- **nuclei now completes and validates discovered services, instead of a killed carpet-bomb** — Two changes. (1) The web-nuclei wall-clock cap is raised 30m → 2h (`apps/nuclei/collector.py`) and the rate limit lowered 150 → 100 rps: on real web-bearing targets nuclei is the single highest-value tool, but the old 30-min wall SIGKILL'd it mid-run — it reported a false `0` on one infra-heavy target (killed at ~4% done) while *completing* with **36** and **42** findings on two web-bearing targets. The run still fits under the 4h scan budget, and if a very large target exceeds 2h it now raises `ToolTimeout` (honest `partial`) rather than a misleading 0. (2) `nuclei_network` added to the Full Scan workflow (migration `0020`): Full Scan previously ran only web nuclei, so nuclei's active protocol probes never reached the non-web services (ftp/smtp/imaps) that naabu/nmap discover — exactly where nmap's version-string CVE lookup produces nothing because `service_detection` couldn't grab a banner. **Why:** the goal is max value without missing findings; time is not the constraint (48h budget), so completion + gentleness beat a fast-but-truncated scan. **Evidence:** three-target Full Scan comparison — nuclei was the #1 finding source on both web-bearing targets (36, 42), and the infra-heavy target's `0` was proven a kill artifact, not a true negative.

- **Orphaned `pending` scans no longer block a domain for hours** — The stuck-scan watchdog reaped `pending` and `running` scans on the same `SCAN_TIMEOUT_MINUTES` (240m) cutoff, but a pending scan is a different failure: if the qcluster worker restarts between a `ScanSession` being enqueued and its Django-Q task being picked up, the task packet is lost and the session stays `pending` forever. Because the per-domain concurrency guard counts `pending` scans as active, that orphan blocked every new scan for the domain until the 4h running cutoff finally caught it. Fix: give `pending` scans their own, much shorter cutoff via a new env-tunable `SCAN_PENDING_TIMEOUT_MINUTES` (default 60m); `running` scans keep the full `SCAN_TIMEOUT_MINUTES` budget so a healthy long scan is still never flipped mid-run. No migration needed — `ScanSession.start_time` is `auto_now_add`, so it already carries the creation time a pending scan is measured against. **Why:** a scan that never started running doesn't need the 4h running budget before it's declared dead; sharing that budget let one lost task wedge a domain far longer than any queue wait could justify. **Evidence:** data-oriented — a scheduled scan was observed sitting in `pending` for ~6h and blocking new scans for that domain after a worker restart.

- **Tool failures are no longer hidden behind `completed`** — Every collector swallowed a missing binary or a wall-clock timeout into `return []`, which the workflow runner could not distinguish from a genuine "ran fine, found nothing" result — so a broken or timed-out tool recorded `status=completed` with no error and the scan rolled up to `completed`. New typed exceptions (`ToolTimeout`, `ToolBinaryMissing` in `apps/core/workflows/exceptions.py`); the 12 collectors whose external binary is essential (nuclei, dnsx, naabu, subfinder, amass, alterx, katana, httpx, nuclei_network, nmap, cloud_assets, takeover_check) now raise instead of returning empty, so the runner — which already marks any raising step `failed` → run `partial` — surfaces the failure. Per-target timeouts inside loops (nmap per-IP) still degrade rather than fail the whole tool, and tools whose binary is optional/supplementary (tls_checker's nmap cipher-enum, historical_urls' gau/waybackurls) stay best-effort by design. Adds a `verify_tools` management command that audits a scan per-tool (preflight binary presence + attributed output counts by `source`, not the misleading `findings_count`). **Why:** this is the root cause behind "how do we know every tool actually ran" — failure and clean-empty were coded to look identical everywhere, so a silently-broken tool was invisible in both the API and the dashboard. **Evidence:** data-oriented — on a Full Scan of the reference target, nuclei ran to its exact 1800s timeout wall, produced 0 findings, recorded `error=none`, and the session still showed `completed`; a grep then confirmed all 14 collectors shared the same swallow pattern.

- **Django bumped to 5.2.16** (#167) — clears freshly-disclosed advisories PYSEC-2026-2090/2091/2092, which pip-audit flags on every CI run against 5.2.15.

- **Full scans now complete instead of dying at exactly 2 hours** (#157, #158) — The Django-Q2 `Q_CLUSTER` config killed every large scan. `timeout: 3600` (1h) hard-killed the worker mid-scan, then `retry: 7200` re-queued a zombie task at exactly 2h — the `retry` comment claimed it "disables retries" but Django-Q2 disables re-queue via `max_attempts`, which was unset. Fix: add `max_attempts: 1` (the real no-requeue switch), and make the timeout a **derived** value instead of a guess — set above the worst-case sum of per-tool caps (~3.4h, dominated by `nuclei_network`'s 1h cap in Phase 7), landing at 4h. The watchdog `SCAN_TIMEOUT_MINUTES` is raised 90m → 240m to stay ≥ the worker timeout, so it only reaps genuinely orphaned scans (dead worker) and never flips a healthy long-running scan to `partial` mid-run. All three knobs are env-tunable (`Q_TASK_TIMEOUT`, `Q_TASK_RETRY`, `SCAN_TIMEOUT_MINUTES`) with a guard forcing `retry > timeout`, and a regression test (`test_qcluster_config.py`) locks the three invariants against future drift. **Why:** the three timers silently contradicted each other, so no scan whose natural runtime exceeded 1h could ever finish. **Evidence:** data-oriented — every failed scan of the reference target since late May ran for almost exactly 2h, matching the `retry: 7200` re-queue window rather than any scan-specific cause.

- **nuclei no longer downloads templates from GitHub mid-scan** (#161, #162) — nuclei templates were never baked into the Docker image (the Dockerfile installed only the binary), and the template directory lives on the ephemeral container filesystem — only `/app/data` and `/app/logs` are on PVCs. So the first nuclei scan on every fresh pod (i.e. after every redeploy) tried to download the entire template repo from GitHub *during the scan* and hung. Fix bakes templates at build time (`RUN nuclei -update-templates`) and adds `-disable-update-check` to the scan command so no template/version network activity ever happens at scan time. **Why:** this was the true root cause behind the reference target's full scans never finishing — separate from the timeout config above. **Evidence:** data-oriented — reproduced on the prod worker: with templates absent nuclei stalls at `nuclei-templates are not installed, installing...`; session 19's nuclei step ran **236.8 min on just 17 URLs** (every other tool combined took ~15 min) and contributed 0 findings before the watchdog killed it. Resolves [#161](https://github.com/cybersecify/OpenEASD/issues/161).

- **nuclei subprocess timeout hardened** (#148, #156) — Redirect nuclei's stdout/stderr to temp files and `wait()` on the process instead of `communicate()`, which could block forever on a pipe inherited by an escaped child (interactsh poller, resolvers) even after the process group was SIGKILL'd. Also kill the whole process group on timeout, and recompute `total_findings` when the watchdog reaps a partial scan so it reports its real count instead of 0. **Why:** a wedged `communicate()` held the single worker thread until the session watchdog reaped it, and reaped-partial scans were showing 0 findings despite completed steps having written to the DB.

- **Kubernetes deploy mechanics** (#155) — Set `imagePullPolicy: Always` on all containers and switch the deployment strategy to `Recreate`. **Why:** the mutable `:latest` tag was not being re-pulled (k8s defaulted to `IfNotPresent`, silently running the old build), and a rolling update deadlocked on the single RWO data PVC — the new pod stayed `Pending` on the volume while the old pod refused to terminate. `Recreate` tears the old pod down first.

- **Dependency CVE bumps** (#147) — cryptography, pypdf, msgpack, pydantic-settings raised to clear disclosed advisories carried in the published image.

- Remove dead `requirements.txt` (#120) — the project uses `pyproject.toml` + `uv`; the stale file misled contributors.

### Changed

- Dependency and CI-action updates via dependabot (#124, #144, #145, #146, and the weekly `github-actions` cadence).
- Docs: expand commit-prefix table + DCO guidance (#128); document the fork workflow, fix the dev-setup port, add a PR template (#127); correct the tool count in README/CLAUDE.md (#121).

---

## [v0.8.0] — 2026-06-10

### Added

- **Domain authorization enforcement** — New `DomainAuthorization` model (OneToOne to `Domain`) records who authorized a domain for scanning, when, how (Domain Owner / Written Consent / Bug Bounty Program), and an optional reference document. Managed entirely in Django admin as a `StackedInline` inside the Domain change page. The domains list gains an **Authorization** column and a **By auth type** sidebar filter so unauthorized domains are immediately visible. The React **Scan** button is disabled for unauthorized domains with a tooltip explaining where to fix it. `POST /api/scans/start/` enforces the gate server-side (HTTP 403 `DOMAIN_NOT_AUTHORIZED`) as the authoritative check — React gating is UX-only. **Why:** OpenEASD's own README states it should only be used against domains the operator owns or has written authorization to test. Without an enforcement layer, there was no mechanism to ensure that constraint — the authorization model closes that gap and creates an auditable record of consent for each domain in the pipeline.

- **`Makefile`** — New project-root `Makefile` with targets: `make setup` (uv sync + migrate + npm install), `make dev` (Django on :8001 + Vite HMR dev server + `qcluster` worker — all three required for scans to execute), `make backend` / `make frontend` / `make worker` (individual processes), `make test` / `make test-all`, `make lint` / `make format`, `make shell`, `make createsuperuser`, `make clean`. **Why:** the project had no standardised dev-workflow entry point — contributors had to read CLAUDE.md and manually start three processes in separate terminals.

- **SBOM + SLSA provenance in published images** (#115) — `docker/build-push-action` now invoked with `sbom: true` and `provenance: mode=max`. Every published image carries a Software Bill of Materials (SPDX format) and a build attestation baked into the manifest, retrievable via `docker buildx imagetools inspect`. **Why:** OpenEASD is a security tool — reviewers reasonably ask whether the tool itself is trustworthy. SBOM + provenance are the standard cryptographic answers; without them the trust story relied on "read the Dockerfile."

- **GitHub Actions pinned to commit SHAs** (#115) — every `uses:` reference in `ci.yml` and `codeql.yml` pinned to a full commit SHA with the version in a trailing comment. Dependabot's `github-actions` ecosystem keeps the pins current on a weekly cadence. **Why:** closes the supply-chain attack vector where a compromised Action could silently rotate malicious code into the build via a re-tag of `v4` (the well-known `tj-actions/changed-files` attack pattern).

- **`Supply chain transparency` section in README** (#115) — discoverable trust narrative covering: what's in the image (with cited upstream sources), how the image is built (CI + SBOM + provenance), what we don't do (no telemetry, no callbacks, no auto-update), continuous security checks (CodeQL + bandit + pip-audit), and build-from-source instructions. Names the one remaining gap honestly (cosign signing — roadmap).

- **CodeQL badge** in README header alongside CI / Docker / License badges. **Why:** signals continuous semantic security analysis at a glance.

### Fixed

- **Vite dev server config** — `vite.config.js` `base` was hardcoded to `'/static/'`, breaking the Vite dev server (assets 404'd). Now conditional: `'/static/'` for production builds, `'/'` for `vite dev`. Proxy target updated to `:8001` to match the new Makefile port, allowing both projects to run simultaneously in local dev.

- **Missing `qcluster` in dev target** — The initial `make dev` only started Django + Vite. Scans queued but never executed because the Django-Q background worker (`qcluster`) was not running. Added `qcluster` as the third process in `make dev`.

- **JWT access token no longer leaks in report download URLs** (#116) — CSV/PDF download buttons on the scan detail page used to embed the access token in the URL query string (`/reports/<uuid>/csv/?token=<jwt>&...`). Tokens leaked into browser history, `Referer` headers, server access logs, and proxy caches. The frontend now downloads reports via authenticated `fetch()` + Blob, sending the token in the `Authorization: Bearer` header — never in any URL. The backend gained Bearer-header support alongside the existing session and (now-deprecated) `?token=` paths; the query-param path is documented as removal-target for a future release. **Why:** the existing pattern violated OAuth 2.0 RFC 6750 §2.3 ("URI Query Parameter is NOT RECOMMENDED ... due to the security deficiencies"). Flagged during pre-launch audit.

- **`katana` now installed in the runtime Docker image** (#115) — v0.7.1's `tools_healthcheck` flagged `katana: binary not found` because the Dockerfile install line was missing, even though `apps/katana/` was registered as a Phase 10 tool. Closes the "17 advertised tools, 16 actually working in Docker" gap.

- **README hero contradicted its own audience section** (#118) — Hero pitched "red teamer ... on a target you're engaged with" — contractor-doing-engagement framing — while the audience section excludes "pen testers running one-shot deep enumeration of a single target." Reframed to "targets you're authorised to test" so the hero matches the audience cards.

- **pyjwt 2.12.1 → 2.13.0** (#115, #116) — clears 4 advisories disclosed 2026-06-04: PYSEC-2026-175, -177, -178, -179. pyjwt is transitive via `ninja-jwt`. Without this bump every published Docker image carried four known CVEs in its JWT auth path.

- **django 5.2.14 → 5.2.15 and pip 26.1 → 26.1.2** (#116) — clears 6 advisories disclosed 2026-06-08: PYSEC-2026-197, -198, -199, -200, -201 (django) and PYSEC-2026-196 (pip).

---

## [v0.7.1] — 2026-06-02

### Added

- **Cloud asset enumeration (`apps/cloud_assets`)** — New Phase 4 tool that runs [`cloud_enum`](https://github.com/initstring/cloud_enum) to enumerate publicly accessible buckets across AWS S3, Azure Blob Storage, and GCP Storage. Keywords are derived from the apex domain label and the leftmost label of each discovered subdomain (minimum length 3, deduped). An open bucket is emitted as a `high`-severity Finding with `extra.provider`, `extra.bucket_name`, and `extra.url`. **Why:** publicly readable cloud storage is one of the most common and highest-impact external-exposure findings — credentials, backups, and customer data are frequently left world-readable by teams that forgot a bucket was ever created. The takeover-check tool (Phase 4) already probes DNS; this tool runs in parallel to close the cloud-storage gap without touching any core files. `TOOL_CLOUD_ENUM` env var configures the binary path.

### Fixed

- **Docker build: `git` missing from runtime stage** — `uv pip install git+https://github.com/initstring/cloud_enum.git` requires the `git` binary at build time, but the runtime `apt-get install` block only included `curl`. Added `git` to the same layer. Fixes CI Docker Build job failure introduced in #100.

---

## [v0.7] — 2026-05-31

### Added

- **Phase groups in tool registry** — Added `phase_group` field to `tool_meta` for all 17 tools, grouping them into five EASD-aligned labels: *Domain Intelligence*, *Surface Enumeration*, *Port Discovery*, *Network Exposure*, *Web Exposure*. The registry exposes `get_tool_phase_groups()` for consumers (API, UI). No behavior change to scanning — purely metadata for display and grouping.

- **Subdomain permutation (`apps/alterx`)** — New Phase 2 tool that runs [alterx](https://github.com/projectdiscovery/alterx) against every subdomain already discovered by subfinder/amass, generating mutation candidates (e.g. `api-dev.`, `api2.`, `staging-api.`) and saving them as `Subdomain` rows. dnsx (Phase 3) resolves them in the same pass as all other subdomains, so permutation-discovered hosts flow automatically into the full pipeline. Noise is kept low by deduplicating against already-saved subdomains before inserting.

- **Historical URL discovery (`apps/historical_urls`)** — New Phase 9 tool that runs [`gau`](https://github.com/lc/gau) and [`waybackurls`](https://github.com/tomnomnom/waybackurls) against every session subdomain and the root domain, pulling historically-archived URLs from Wayback Machine, AlienVault OTX, and Common Crawl. Discovers forgotten endpoints, deprecated API versions, and removed-but-still-deployed paths invisible to live-crawl-only scanning. URLs are saved to the shared `URL` table (same as httpx/katana) so they flow automatically into downstream `web_checker` and `nuclei` scans. Noise filter drops images, fonts, stylesheets, and archives. Dockerfile adds a `history-builder` Go stage that cross-compiles both binaries from source. Resolves [#75](https://github.com/cybersecify/OpenEASD/issues/75).

- **Subdomain takeover detection (`apps/takeover_check`)** — New Phase 4 tool that runs [subzy](https://github.com/PentestPad/subzy) against discovered subdomains and emits a `high`-severity Finding for each subdomain whose DNS points at an unclaimed third-party resource (S3, GitHub Pages, Heroku, Azure, Fastly, etc.). The tool reads from `Subdomain` records (so it picks up everything subfinder/amass found), invokes `subzy run --targets <file> --output <file> --hide_fails`, and writes to the unified `Finding` model with `extra.service` + `extra.raw` for auditability. Dockerfile adds a cross-compiled `subzy-builder` Go stage (`SUBZY_VERSION=v1.2.1`, `CGO_ENABLED=0`, `-ldflags="-s -w"`) since subzy ships no prebuilt binaries — the runtime image gets only the static binary. **Why:** subdomain takeover is one of the highest-leverage external-recon findings (HTTPS-cert-valid phishing surface + same-eTLD cookie/session theft + SSO breakthrough), it's invisible to defenders until exploited, and it was the largest remaining gap in OpenEASD's external attack-surface coverage — none of the existing 14 tools touch dangling DNS. **Hypothesis:** real engagements + small-team scans against orgs with 5+ years of subdomain history will surface 0-3 takeover findings per scan, all genuinely actionable (verified by manually visiting the subdomain). **Evidence:** speculative on per-scan finding count — depends entirely on the target's DNS hygiene. Data-oriented on the gap-closure claim — `grep -r "takeover\|dangling" apps/` returns no matches before this commit, confirming the category was absent. Tool choice and integration approach informed by closed [PR #82](https://github.com/cybersecify/OpenEASD/pull/82) from [@zeroknowledge0x](https://github.com/zeroknowledge0x); implementation rewritten to match the project's five-file plugin pattern, fix the analyzer field name (`extra` not `extras`), use subzy's actual CLI flags (`--output <file>` for JSON, no `--json` flag exists), and add the missing integration glue (tests, `INSTALLED_APPS`, Dockerfile install, CHANGELOG).

- **Optional report CTA (`REPORT_CTA_URL` + `REPORT_CTA_TEXT`)** — Two new env-var settings that, when both are set, append a call-to-action block to PDF reports and a CTA row to CSV exports. Both default to empty, so self-hosters see no behavior change. **Why:** the PDF/CSV reports are the final artifact a scan user sees, and without a configurable touchpoint there's no way for a deployment to point readers at a follow-up resource. The mechanism is generic — text and URL are deployment-controlled, not hard-coded in the codebase. Both must be set for the block to render (prevents half-configured deployments from shipping orphan text or naked URLs). Wired into `apps/core/reports/views.py` (CSV writer + PDF template context) and the `templates/reports/scan_report.html` end-of-report block. 9 new unit tests cover empty/half/both configurations for CSV and the rendered HTML the PDF view passes to `pisa`.

---

## [v0.5] — 2026-05-31

### Added

- **HSTS checks in web_checker** — Two new findings: `missing_hsts` (medium) when an HTTPS response carries no `Strict-Transport-Security` header, and `weak_hsts` (low) when `max-age` is present but below the 6-month threshold (15 552 000 s). HTTP URLs are skipped — HSTS only applies to HTTPS. 4 new unit tests cover missing, HTTP-skip, weak, and strong cases. Contributed by [@xiaoke949](https://github.com/xiaoke949).

- **Backport-aware CVE matching in nmap analyzer** — The nmap collector now consults a curated `backports.json` knowledge file before emitting CVE findings, so distro-backported fixes are recognised. Concretely: Ubuntu 24.04 packages OpenSSH as `9.6p1-3ubuntu13.16`. The CVE-2024-6387 (regreSSHion) fix landed in `3ubuntu13.3` (USN-6859-1, July 2024), but the upstream version string stays `9.6p1` — so `nmap --script vulners` (and any tool wrapping it) reports CVE-2024-6387 as present even though the binary is patched. The analyzer now parses the distro hint from the banner, looks up `(distro, CVE, package)` in `backports.json`, and demotes the finding to `info` with `extra={"backport_applied": true, "first_fixed_in": "..."}` if the installed version is at or beyond the fixed version. The seed dataset covers the noisiest false positives on Ubuntu LTS and Debian stable (OpenSSH, OpenSSL, nginx, Apache HTTPD, Postfix). **Why:** scan-output quality is the differentiator vs. running `nmap --script vulners` directly — without backport awareness, every Linux scan carries the same false positives the upstream tool does, eroding trust in OpenEASD's other findings. **Hypothesis:** backport-aware filtering will reduce the false-positive count on Ubuntu/Debian targets significantly (rough estimate ~80% reduction on OpenSSH-related CVEs for fully-patched LTS hosts), improving end-user trust without adding new false negatives. **Evidence:** data-oriented — the issue was opened after observing this exact pattern on a real Ubuntu 24.04 host during a production scan (host's installed `openssh-server` had the regreSSHion backport but nmap NSE vulners still flagged CVE-2024-6387). Contributed by [@turfin-logic](https://github.com/turfin-logic).

- **Product and architecture docs** — `docs/PRD.md` (5W PM view: audience, 11 attack vectors, constraints, anti-features, success criteria) and `docs/DESIGN.md` (full architecture reference: core apps, tool registry, scan pipeline phases, data model, REST API, frontend, deployment topologies).

### Changed

- **GitHub Flow adopted** — Replaced the solo-developer "commit directly to main" workflow with a `feat/` / `fix/` branch + PR + squash-merge process. CLAUDE.md updated accordingly.

- **React 19 + Vite 8 + @vitejs/plugin-react 6** — Full frontend stack upgrade. All three packages must move together (`@vitejs/plugin-react` v6 requires `vite@^8`); Dependabot grouping updated to reflect the coupling.

- **Co-founder attribution** — LICENSE and README Author footer updated to credit both Rathnakara G N and Ashok S Kamat with LinkedIn profile links.

- **Dependabot grouping fixed** — `react-stack` group now lists `vite` (exact name) alongside `react`, `react-dom`, and `@vitejs/plugin-react` so the packages always bump atomically. Tailwind 4 and Ubuntu 26.04 PRs are kept closed — both require dedicated migration work before adoption.

### Dependencies updated

Python: `psutil`, `slack-sdk`, `certifi`, `pytest-asyncio`, `django-stack` (Django + django-ninja + django-q2), `reportlab`, `aiofiles`, `tqdm`, `cachetools`, `docker`, `pandas`, `jinja2`, `python-dateutil`, `tenacity`, `numpy`.

Frontend: `lucide-react`, `postcss`, `react 19`, `react-dom 19`, `vite 8`, `@vitejs/plugin-react 6`.

GitHub Actions: `actions/setup-node`, `docker/login-action`.

### Feature additions (May 2026)

#### Added

- **Continuous monitoring** — Domains can now be configured to rescan automatically on a schedule (6h / 12h / 24h / 48h / weekly). Each domain gets its own Django-Q2 schedule entry managed via `sync_domain_monitoring_jobs()`. Monitoring jobs are synced on scheduler startup, on every monitoring config change, and when a domain is deactivated or deleted — no orphan jobs. UI: "Monitor" button per domain row in the Domains page; "Monitoring" column shows current interval.

- **Subscan** — Re-run specific tools (e.g. just Nuclei + TLS Checker) on an existing completed scan's assets without repeating discovery. A subscan copies the parent session's Subdomain/IPAddress/Port/URL graph with FK remapping, then runs only the selected tools. Discovery tools (subfinder, amass, dnsx, naabu, service_detection) are excluded from the subscan tool picker because ports are already classified. UI: "Re-scan Tools" button on completed scan detail; checkbox list with amber warning about stale assets.

- **Notifications UI** — Slack and Teams webhook URLs and severity threshold are now configurable from the app without restarting the container. Settings are stored in a `NotificationConfig` singleton model (DB-first, env-var fallback). The Notifications page includes a per-channel Test button that fires a live message, plus an alert history table with pagination. Also fixed a bug where `_dispatch_alerts` returned early if only Teams was configured (was checking `SLACK_WEBHOOK_URL` only).

#### Changed

- **APScheduler replaced by Django-Q2 scheduling.** `apscheduler` and `django-apscheduler` packages removed. All scheduling now uses `django_q.models.Schedule` — the same system already running for background task execution. One fewer dependency pair, one fewer background thread, all schedules visible in the Django-Q2 admin section. `croniter` added as a required dependency for CRON-type schedules.

#### Fixed (code review)

- `toggle_domain` and `delete_domain` now call `sync_domain_monitoring_jobs()` so deactivated/deleted domains immediately lose their monitoring schedule entries rather than continuing to fire scans against non-existent domains.
- `setup_core_schedules()` calls `sync_domain_monitoring_jobs()` on startup, so per-domain monitoring jobs survive container restarts and fresh deployments with pre-seeded databases.
- `create_subscan_session` dead code fixed: the resolved `workflow` (with default fallback) is now actually used in `ScanSession.create` instead of `parent.workflow` directly, which could be `None`.
- `_detect_deltas` now excludes subscans (`parent_session__isnull=True`) when looking for the previous scan to compare against. Without this fix, the next full scan after a subscan would show spurious "new findings" for everything the subscan didn't run.

---

### Pre-launch hardening (May 2026)

Audience-and-positioning pass: OpenEASD targets the security community
specifically — in-house security/IT teams, small security consultancies,
security learners. The pre-launch work below tightens the load-bearing
"one `docker run` and it works" promise before any public announcement.

#### Fixed
- **README claims-trace audit — two drifts corrected.**
  Walked every customer-visible README claim through `apps/*/analyzer.py`
  and `apps/*/scanner.py` to confirm the code implements what we say it
  does. Two drifts found:
  (a) **"Nuclei Network (319 templates)"** → reworded to "service-aware
  nuclei network templates against non-web ports." The number `319` doesn't
  appear anywhere in code and is a stale snapshot — nuclei-templates updates
  upstream, the count drifts every release. Timeless wording avoids the drift.
  (b) **"PyJWT — JWT token creation and validation"** → corrected to
  "django-ninja-jwt — JWT auth for the Ninja API." `pyproject.toml` has
  `django-ninja-jwt>=5.0`; `apps/core/api/ninja.py` imports `ninja_jwt`.
  PyJWT is at best a transitive dependency, not the auth library we use.
  All other Pipeline/Features claims trace cleanly: DNS/SPF/DMARC/DKIM/RDAP
  in `domain_security/scanner.py` and `checks/rdap.py`; web headers/cookies/
  CORS in `web_checker/analyzer.py`; cert/cipher/protocol in `tls_checker/
  analyzer.py`; SSH config (root login, weak kex/cipher/MAC, SSHv1) in
  `ssh_checker/analyzer.py`; naabu top-100 confirmed in `collector.py:43`;
  service_detection nmap -sV in `detector.py:15`; continuous-monitoring
  intervals 6h/12h/24h/48h/weekly in `domains/api.py:151`
  (`VALID_INTERVALS = {6, 12, 24, 48, 168}`). HSTS — the historic drift
  case — is still not implemented in `web_checker/analyzer.py`, but the
  README never claimed it, so no drift.
  **Why:** the verification discipline ("claims trace to code, not to other
  documentation") is the load-bearing rule that prevents customer-facing
  copy from drifting out of sync with what the tool actually does. Audit
  pass run pre-v1.0 launch.

- **`step_result.findings_count` no longer mislabels assets as findings.**
  The runner counted *whatever* the tool's runner returned and wrote it to
  `findings_count`. For finding-producing tools (nmap, domain_security,
  tls_checker, ssh_checker, nuclei, nuclei_network, web_checker) that's
  correct — they return Finding rows. But for asset-producing tools
  (subfinder, amass, dnsx, naabu, httpx, service_detection) the return value
  is a list of Subdomain/IPAddress/Port/URL records, not Findings. Result:
  API responses showed nonsense like `"subfinder": findings_count: 10` when
  the Findings table actually had zero rows for subfinder. Fix: the runner
  now consults `tool_meta.produces_findings` (already declared per app) and
  leaves `findings_count` at 0 for asset tools. Per-tool asset totals are
  unchanged — they're visible at the session level (`subdomains_total`, `ips`,
  `ports`, `urls` in `/api/scans/<uuid>/status/`).

#### Added
- **`/api/scans/findings/` now accepts `?session_uuid=<uuid>`.**
  Before: callers (including me, today, debugging a watchdog issue) tried
  `?session_uuid=<uuid>` and got the default `latest_session_ids()` view back
  — silently. Django Ninja accepts unknown query params without complaint, so
  the filter looked like it worked but returned unrelated data. Cost ~20 min
  of "where are my findings?" Now: `session_uuid` is a real query param
  alongside `session_id` and does an internal UUID→session lookup; unknown
  UUID returns 404 (no longer a silent default). Finding serializer also now
  includes `session_uuid` so external clients holding the UUID don't have to
  do a separate lookup. **Why:** external clients rarely have the integer
  `session_id` on hand (UUIDs are what /api/scans/ and /api/scans/<uuid>/
  hand back). The mismatch was a guaranteed UX trap for anyone exercising
  the API directly.

- **`tools_healthcheck` management command, run at container startup.**
  Probes each external tool (subfinder, dnsx, naabu, httpx, nuclei, nmap, amass)
  with a tiny known-good target — e.g. `naabu -host 1.1.1.1 -p 443`,
  `dnsx -a` with `google.com` on stdin — and prints PASS/FAIL per tool in the
  container logs. Catches the four silent-failure modes that have repeatedly
  bitten this project: (a) binary missing or wrong PATH, (b) subprocess
  timeout, (c) non-zero exit, (d) **exit-zero-with-empty-stdout** — the
  specific Mac/Colima symptom that produced "0.8-second full scans with only
  DNS findings" earlier this week. `docker-entrypoint.sh` runs it after
  migrate/collectstatic, before `exec`. Always exits 0 — observability, not
  gating. Operators read the logs; users can still log into the UI to
  investigate. `--quick` flag runs version checks only (no network) for fast
  local sanity-checks. **Why:** every time scans have returned 0 findings on
  a real target, the cause was an upstream tool failing silently and we had
  no early warning — users would only notice after a scan finished suspiciously
  fast or produced an obviously-thin report. A 30-second boot probe surfaces
  the failure immediately in the container logs, where any operator
  troubleshooting "why does my scan show nothing" will look first.

#### Fixed
- **Stuck-scan watchdog no longer throws away pre-nuclei findings.**
  Before: any scan still in `running` after `SCAN_TIMEOUT_MINUTES` (default 90)
  was marked `failed`, end of story. In practice that meant scans against real
  domains with web URLs almost always hit the watchdog mid-nuclei (web vuln
  scan across community templates routinely exceeds 1 hour), and the user
  saw `failed` + no PDF + the React UI hid all the findings from steps 1–9
  even though they were sitting in the database. Three back-to-back production
  scans on the production instance reproduced this exactly —
  domain_security/subfinder/dnsx/naabu/service_detection/httpx/nmap/tls_checker/ssh_checker
  all completed with real findings, then the scan was reaped while nuclei was
  still running and the entire report disappeared from the UI. Now: the
  watchdog distinguishes two cases — if at least one step has `status=completed`
  the session is marked `partial` (new status), otherwise `failed`. Any
  in-flight step's status flips to `failed` with `error="reaped by watchdog
  after Nm"` so the UI shows exactly what was killed. Partial sessions surface
  in `latest_session_ids`, dashboard tiles, delta detection, and the findings
  list the same way completed sessions do; the React Badge renders `partial`
  in amber (not red) and CSV/PDF report buttons are enabled.
  **Why:** the load-bearing "run a scan against your domain, get a report"
  promise was being broken by an internal implementation timeout that the user
  has no visibility into. Marking partial-completion as a first-class outcome
  is the smallest change that restores the promise without re-architecting
  nuclei's runtime. The deeper fix — bounding nuclei templates or extending
  the worker timeout — is still on the table but is product policy, not a bug
  fix.

- **All collector subprocess invocations now pass `stdin=subprocess.DEVNULL`.**
  Defensive fix applied to all 9 collector callsites: `subfinder`, `amass`,
  `dnsx`, `naabu`, `httpx`, `nuclei`, `nuclei_network`, `nmap`, and
  `service_detection`. Without an explicit stdin, the subprocess inherits the
  parent (Django-Q worker) process's stdin, which has been observed to make
  Go binaries (dnsx, naabu) hang or silently return 0 records — the exact
  pattern that produced 0.8-second "full scans" with only DNS findings.
  **Why:** local reproduction confirmed `stdin=DEVNULL` is the difference
  between dnsx hanging at 60s and returning records in ~1s when invoked
  via Python subprocess. The same defensive flag is applied to all
  collectors uniformly because the failure mode is silent — better to
  fix it everywhere than chase tool-by-tool. **Honest caveat:** root cause
  for the underlying behavior was not fully pinned down (Go runtime + stdin
  inheritance + container networking on macOS Colima all contributed to
  noisy reproduction). The patch is safe regardless: closing inherited
  stdin can't break tools that don't read it, and it fixes the ones that
  do. Deployment to a real Linux node is the cleanest confirmation.

- **Apex domain is now resolved Python-side at pipeline start, not relying on dnsx.**
  Re-test on the all-fixes image showed dnsx still returning 0 records for the
  seeded apex (took 13s, returncode 0, empty stdout) — even though running the
  exact same `dnsx -l <file> -a -aaaa -resp -json -silent` command via a bare
  `python3 -c "subprocess.run(...)"` inside the same container worked in 1
  second and returned the expected `{"host":"example.com","a":["<ip>"]...}`.
  The failure mode is only reproducible inside the Django-Q worker process —
  some interaction we couldn't pin down (signals? cgroup? Goroutine scheduling
  under the worker fork?). Now: a new `_seed_apex_into_assets()` helper in
  `apps/core/scans/pipeline.py` uses `dns.resolver.resolve()` (dnspython,
  already a dependency) to resolve the apex's public A/AAAA records and seed
  the `IPAddress` table directly, marking the seeded `Subdomain` active.
  dnsx still runs and still resolves anything subfinder/amass discovered —
  this is a *guarantee* on the apex case, not a replacement for dnsx.
  **Why:** the load-bearing first-run experience ("scan my domain → get
  open ports + web vulns") can't depend on a tool that fails silently in
  one specific runtime. Python-side resolution is fast (<1s), uses the
  same NXDOMAIN/timeout semantics, and bypasses the dnsx-in-django-q issue
  entirely. The dnsx failure is logged for future investigation but no
  longer blocks the user-visible value.

- **Tool path defaults now use PATH lookup instead of hardcoded pdtm location.**
  Before: `settings.py` set `TOOL_SUBFINDER`, `TOOL_DNSX`, `TOOL_NAABU`,
  `TOOL_HTTPX`, `TOOL_NUCLEI` to `~/.pdtm/go/bin/<tool>` by default — the
  ProjectDiscovery `pdtm` install location on dev machines. In the published
  Docker image those binaries live at `/usr/local/bin/` (per `Dockerfile:90`),
  so every ProjectDiscovery scanner failed with `Binary not found:
  /root/.pdtm/go/bin/...` and silently returned zero results. Now: defaults
  are bare names (`"subfinder"`, etc.), so `subprocess.run` resolves via PATH —
  which covers all three deploy targets (container, pdtm-installed dev,
  system-installed dev). The `TOOL_*` env vars still work for overrides.
  **Why:** the load-bearing test (scan `example.com`, get IPs/ports/URLs)
  was failing solely because of this — even with the pipeline-seed fix in place,
  dnsx couldn't resolve the seeded subdomain because the binary lookup failed.

- **Removed invalid `-json` flag from amass collector.**
  Before: `apps/amass/collector.py:33` invoked `amass enum -d ... -json -silent`,
  but amass v4.2.0 (the version bundled in the Docker image) dropped the `-json`
  flag. Result: amass exited code 1 with stderr `flag provided but not defined:
  -json` → 0 subdomains returned, silent failure. Now: flag dropped; amass v4
  outputs plain-text subdomains line-by-line, which the existing parser already
  handles (line 94 fallback).
  **Why:** amass should actually run when enabled. Bumping amass between major
  versions without revisiting the CLI flags was the real bug — adding a CI
  smoke-test that runs each tool with a tiny target would catch this kind of
  drift earlier.

- **Scan pipeline now seeds the input domain as a Subdomain at scan start.**
  Before: subfinder/amass populated the `Subdomain` table with their *output*,
  and every downstream tool (dnsx → naabu → service_detection → nmap / tls_checker /
  ssh_checker / nuclei_network → httpx → nuclei / web_checker) read from that
  table. The apex/input domain was never inserted as a seed. So scanning a leaf
  host (e.g. `example.com`) or any domain with no public subdomains produced
  *only* domain_security DNS findings — every other tool ran with an empty input
  set and reported zero. A real first-run test against `example.com` produced
  0 IPs, 0 ports, 0 URLs, 0 web vulns. Now: `Subdomain.objects.get_or_create(...)`
  inserts the input domain with `source="seed"` before the workflow runner kicks.
  **Why:** the most common first-time scan ("scan my own domain") doesn't always
  have a long subdomain list. Without the seed, those users get an empty-looking
  report and conclude the tool is broken before they ever see what it can do.

- **`/api/docs` (OpenAPI/Swagger UI) is now always enabled.**
  Before: `NinjaAPI(..., docs_url="/docs" if settings.DEBUG else None)` — so docs
  returned 404 in production. README line 239 and CLAUDE.md both directed users
  to this URL as the API discovery surface. Now: `docs_url="/docs"` unconditionally.
  **Why:** the documented URL has to actually work. Schemas are visible in source
  code already; exposing the auto-generated docs doesn't leak anything that
  isn't already public. Routes still enforce JWT auth — the docs are descriptive,
  not a bypass.

- **`/api/workflows/tools/` response now includes `produces_findings`.**
  Before: each tool's `apps.py` declared `produces_findings: True/False` in
  `tool_meta`, but the API endpoint built tool dicts manually with only `key`,
  `label`, `phase` — dropping the field. Frontend treated it as `null` for all
  12 tools. Now: added `get_tool_produces_findings()` registry helper and
  surfaced the field in the response.
  **Why:** the field exists for a reason (it lets the UI flag which steps will
  actually populate the Findings table). A `null` everywhere makes the field
  meaningless.

- **APScheduler now starts in the qcluster process only — not in gunicorn workers.**
  Before: the guard `RUN_MAIN != "true" and not SERVER_SOFTWARE` returned False
  for *every* gunicorn worker (SERVER_SOFTWARE is set in all workers), so the
  scheduler started N times in a 2-worker single-container Docker setup. Logs
  showed "Scheduler started — daily scan at 02:00 IST" twice, and APScheduler
  jobs were registered in both workers, leading to duplicate firings of every
  scheduled scan. Now: scheduler initialises only when `qcluster` is in
  `sys.argv` — anchoring on the Django-Q2 task worker process, which exists in
  exactly one copy across Docker single-container, K8s split (worker pod), and
  local dev (when `manage.py qcluster` is running).
  **Why:** the scheduler logically belongs with the task worker (its job is to
  enqueue scan tasks). Coupling it to the web tier was an accident of where
  `AppConfig.ready()` happens to run. One local-dev caveat: `manage.py runserver`
  alone no longer fires the scheduler — devs who want the scheduler in dev must
  also run `manage.py qcluster` (which CLAUDE.md already instructs them to).

- **Docker image now serves gunicorn, not Django's dev server.**
  The default `CMD` invoked `python main.py`, which under the hood runs
  `manage.py runserver` — Django's development server, which is single-threaded
  and explicitly *not* for production use. The published `:latest` image
  was therefore unsuitable for production despite the README framing it
  that way. The K8s manifests already used gunicorn (via a command override),
  so this change brings single-container Docker into line with K8s.
  **Why:** the security community will spot a dev server in a "production"
  image immediately, and the credibility cost is large. `main.py` is unchanged
  and remains the local-dev entry point with autoreload.

#### Changed
- **README docker run example now sets `ALLOWED_HOSTS`.**
  Without it, a user accessing via the server's IP from a remote machine
  hits Django's `DisallowedHost` 400 response with no obvious explanation,
  and bounces. The env var was documented further down the README, but
  the example command is what users actually copy.
  **Why:** the load-bearing promise is "copy this one command and it works."
  Friction in the first three minutes is what kills tool adoption in
  this niche.

- **Setup wizard welcome copy now mentions the `admin`/`admin` default.**
  The first-time user has just typed those credentials at the login page,
  is bounced to `/setup`, and gets asked for "Current Password" with no
  context. The minimal fix explains the default once in the welcome copy
  so the field stops feeling arbitrary.
  **Why:** small, but it's right at the front door — five seconds of
  confusion at the first screen colours the rest of the evaluation.

### Verified (no code change required)
- `ghcr.io/cybersecify/openeasd:latest` is publicly pullable — anonymous
  manifest fetch returns 200. (Some packages default to private on GHCR;
  worth re-checking after each new repo's first publish.)
- `gunicorn>=21.2` is in the `[prod]` extras and is installed in the
  Docker image (`pyproject.toml:42`, `Dockerfile:105`).
- **Default workflow is correctly `Infra Scan`, not `Full Scan`.** Migration
  0017 demotes Full Scan and promotes Infra Scan; live test confirms a no-args
  scan kicks off with the 9 Infra Scan tools + auto-injected `service_detection`.
  (Flagged during test as a possible bug because `head -30` truncation showed
  only Full Scan with `is_default=false`; rebuilding the test with a higher
  limit would have shown Infra Scan at id=2 with `is_default=true`.)
