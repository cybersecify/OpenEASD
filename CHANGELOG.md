# Changelog

All notable changes to OpenEASD are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) with a short
**Why** note on non-obvious changes so reviewers don't have to dig through
commits to recover the reasoning.

## [Unreleased]

### Added
- **Findings register UI — the finding-centric primary surface (PR3).** New
  **Findings** page (nav + `/findings`) and `/api/issues/` API (list ranked by
  severity, `summary`, and a `status` endpoint) over the persistent `Issue`
  register. It's a cross-scan issue list — filter by status/severity/domain/
  search — where inline triage **patches `Issue.status`, so a dismissal persists
  across scans** (the whole point of PR2). Targets link to their asset; the
  empty state and header explicitly note "empty ≠ clean — check Scans for
  coverage." This is the visible finding-centric turn, grounded on the asset
  layer (PR1) and the persistent identity (PR2).
- **Persistent Issue register — cross-scan finding identity (finding-centric PR2).**
  New `findings.Issue` model (mirrors `asset_inventory`): one row per
  `(domain, source, check_type, title, target)`, carrying `first_seen`/`last_seen`
  and — the point — a **persistent triage `status`**. A fail-graceful finalize
  rollup upserts issues from each completed full scan, so a **dismissal
  (`false_positive`/`acknowledged`) now survives a re-scan** instead of resetting
  to `open` every run; a `resolved` issue that reappears is re-opened (regression).
  Grounded on the asset layer via `Issue.asset`. Backend/model only — the
  Findings/Issues register UI is the next step. Spec:
  `docs/specs/2026-09-12-finding-centric-ui-direction.md`.
- **Assets inventory UI restored (asset-centric grounding).** Re-introduces the
  persistent **Assets** page (list) + **Asset detail** page over the existing
  `/api/assets/` layer, with a nav entry and `/assets` + `/assets/:id` routes.
  The list filters by kind/status/domain/search, paginates, and shows per-asset
  open-finding severity chips; the detail page shows metadata, findings, and the
  scan timeline. This is step 1 of the finding-centric-grounded-on-asset-centric
  UI direction (`docs/specs/2026-09-12-finding-centric-ui-direction.md`), which
  supersedes the "strictly scan-centric" decision (#406). The `/api/assets/` data
  layer was never removed — this is UI wiring only.

## [v2.15.1] — 2026-09-11

### Fixed
- **typosquat now handles multi-label ccTLD domains (PSL/ccTLD).** The apex was
  split by a naive last dot, so `example.co.uk` became name=`example.co` /
  tld=`uk` — TLD-swap then emitted garbage like `example.co.com` (which never
  resolves) and char-mutations mangled the suffix, so **ccTLD targets got
  effectively no lookalike detection**. `_split_apex` now recognises common
  multi-label public suffixes (`co.uk`, `com.au`, `co.in`, …) and splits on the
  registrable label, so `example.co.uk` → `("example", "co.uk")` and TLD-swap
  yields real lookalikes (`example.com`, `example.net`, …). Curated set (not the
  full ~9k-entry PSL — keeps the worker dependency-free and offline); extend via
  `TYPOSQUAT_MULTI_LABEL_SUFFIXES`.
- **Review cleanup: honest error handling + de-duplication (F4 / F5 / F-dup / comments).**
  - **F4** — `_count_all_findings` no longer swallows a DB error into `0`
    ("clean"): the error propagates so finalize fails honestly, and the stuck-scan
    reaper guards its own recount so a hiccup leaves `total_findings` unchanged
    rather than aborting the watchdog sweep or faking a 0.
  - **F5** — the scan-status endpoint's bare `except: pass` is gone (it now
    queries for the `WorkflowRun` instead of catching "no run yet", so a real DB
    error surfaces); two other broad catches that already log / carry a reason
    got the `# noqa: BLE001` convention tag.
  - **F-dup** — `ai/context.py` dropped its private `_SEVERITY_ORDER` in favour of
    the shared `apps.core.constants.SEVERITY_RANK` (behavior-preserving ordering).
  - **Comments / frontend:** corrected the stale nuclei wall-clock-cap comment
    (6h, not "2h"), the `asn_cluster` phase-vs-phase_group comment, and made
    `Badge.jsx` derive its known-status set from the variant map (one source of
    truth).
- **Consistent 404 response shape across the API (F6).** `get_object_or_404`
  misses rendered Django Ninja's default `{"detail": "Not Found"}`, a second
  shape alongside the `{"error": {"code", "message"}}` envelope every
  `HttpError` uses. Added a single `Http404` exception handler so all 404s —
  current and future `get_object_or_404` call sites — render the standard
  envelope (`{"error": {"code": "NOT_FOUND", …}}`).
- **Phase-group execution resumes cleanly after a crash (F1b).** The per-phase
  DBOS step re-runs the *whole* group on a crash-resume, but within-group
  execution wasn't idempotent — a resume re-created `WorkflowStepResult` rows
  (no `(run, tool)` unique constraint) and re-executed tools that had already
  finished. `_run_single_step` now skips a tool that already reached a terminal
  state and reuses a non-terminal (crashed "running") row instead of duplicating
  it; `run_one_phase_group` skips already-terminal tools up front. Checkpointing
  is no longer only at the group boundary.
- **Manual AI re-triage actually re-runs now (F2).** The `ai_triage` durable task
  deduped on `triage-{session_id}` with `return-existing`, so a second manual
  re-triage returned the prior *completed* workflow and silently did nothing —
  while the UI sat at "running". Dropped the dedupe (each manual run enqueues a
  fresh workflow, matching `agent_step`), and moved the concurrency protection it
  incidentally provided into the `/triage/<uuid>/run/` endpoint as an atomic
  `select_for_update` in-flight guard (two near-simultaneous clicks → one run +
  409). The automatic post-scan triage was unaffected (it runs inline, not via
  this task).
- **Tool consistency pass (F-tool1 / F-tool4 / config drift).** Aligned a few
  tool apps with the conventions their siblings already follow:
  - `domain_security` and `domain_probe` now wrap collect+analyze in
    `try/except → return []` so an unexpected DNS/RDAP/probe error can never
    propagate and fail the whole scan — matching their passive Domain-Posture
    siblings (`breach_check`/`hudson_rock`/`dns_history`).
  - `web_checker` now sends the shared honest User-Agent
    (`settings.OPENEASD_USER_AGENT`) instead of a tool-specific string — it was
    the only tool that diverged, so a target allowlisting the scanner now sees a
    consistent UA across httpx/katana/nuclei/web_checker.
  - Added the missing `default_auto_field` to six tool `apps.py`
    (`cve_intel`, `nuclei_network`, `ssh_checker`, `takeover_check`,
    `tls_checker`, `web_checker`). No migrations (these apps define no models).
  - `cloud_assets` now **propagates** a missing/timed-out `cloud_enum` (F-tool3):
    dropped the upfront `shutil.which → []` silent skip, so the binary-missing
    case raises `ToolBinaryMissing` like every other binary collector and the
    runner marks the scan "partial" instead of a fake "clean". Ruling: binary
    tools propagate, matching `takeover_check` — restoring the intent of the
    earlier "tool failures no longer hidden behind `completed`" change.
  - `domain_security` now honors the configured DNS timeout on **all** lookups
    (F-tool2): `_DNS_TIMEOUT` (`SCANNER_DNS_TIMEOUT`, default 5s) was applied to
    only the lame-delegation probe, so a slow/hung authoritative server could
    stall a scan past the bound. Added `lifetime=_DNS_TIMEOUT` to all six
    `dns.resolver.resolve` calls.

### Security
- **Centralized the domain-authorization gate into one predicate (F3).** The
  "is this domain authorized for active scanning?" check
  (`DomainAuthorization.objects.filter(domain__name=X).exists()`) was hand-copied
  in three places — the scan-start gate, the subscan gate, and the AI agent's
  `gate_subscan_tools`. For a security gate, three copies are a drift hazard; they
  now all call a single `DomainAuthorization.is_authorized(domain)` classmethod,
  so any future change (e.g. authorization expiry) applies everywhere at once.
  Behavior-preserving.
- **Production guards skip only under the pytest runner, not mere importability
  (F-sec2).** The SECRET_KEY and default-DB-password fail-fast guards skipped
  whenever `"pytest" in sys.modules` — so any process that transitively imported
  pytest (a dependency, a debug shell) silently disabled them. A new
  `_under_pytest()` detects the test *runner* via the process entrypoint
  (`sys.argv[0]`), so the guards still skip during `pytest` runs but fire
  everywhere else. (Prod images install only `.[prod]`, so pytest isn't present
  there anyway — this is defense-in-depth.)
- **Removed the `?token=<JWT>` query-param auth on report endpoints (F-sec3).**
  The CSV/PDF report views accepted a JWT in the query string, which leaks into
  browser history, `Referer` headers, server access logs, and proxy caches.
  `_report_auth_required` now authenticates only via Django session or the
  `Authorization: Bearer` header — both SPA report pages already send the header
  (fetch+Blob, never in the URL), so nothing depended on the query-param path; a
  token in the query string is now ignored.
- **Fail fast on the default DB password in production (F-sec1).** `DB_PASSWORD`
  defaulted to `"openeasd"` with nothing stopping a `DEBUG=False` deploy from
  booting on it — a trivial foothold on the database that holds every scan
  result and the encrypted BYOK credentials. A new `_validate_db_password` guard
  (mirroring the existing `SECRET_KEY` guard) raises `ImproperlyConfigured` at
  settings import when `DEBUG=False` and the DB_* path still uses the default
  `"openeasd"`. The `DATABASE_URL` path is exempt (it carries its own creds), and
  the guard is skipped under the test runner. Like the SECRET_KEY guard it
  matches only the **code default**, so the shipped docker-compose / k8s configs
  (which set a real password or `"change-me-in-production"`) boot unchanged.

### Fixed
- **Brand-threat false positives (typosquat + asn_cluster).** Triaging a real
  amnic.com report showed the Brand Threat category badly over-calling: a
  legitimate ccTLD registry (amnic.net = the Armenia Network Information Centre)
  flagged as "active impersonation", and parked lookalikes sharing an AWS/
  Cloudflare/Namecheap IP reported as a "coordinated phishing infrastructure"
  cluster. Three tuning fixes, no new tools:
  - **typosquat now gates "high" on a login form only.** A brand-name string on
    the page is a *review signal* (kept in the description), not proof of
    impersonation — short brand strings legitimately appear in unrelated
    organizations' own names. Brand-mention-alone no longer escalates to high.
  - **typosquat detects domain parking** (known parking/for-sale anycast IPs +
    sale boilerplate on the homepage) and caps a parked lookalike at **low** —
    registrar-default A/MX records are speculation, not the buyer's phishing
    infrastructure. A confirmed login form still outranks the parked signal.
  - **asn_cluster skips generic networks** (hyperscale clouds, major CDNs,
    registrar/parking ASNs — AWS/Cloudflare/Google/Namecheap/etc.) where
    millions of unrelated domains co-locate, *unless* the cluster contains a
    weaponized member. Overridable via `ASN_CLUSTER_GENERIC_ASNS`.
  - (The multi-label-ccTLD apex-split limitation noted here originally is now
    fixed — see "typosquat now handles multi-label ccTLD domains" below.)

## [v2.15.0] — 2026-09-11

### Changed
- **Split "Domain Intelligence" into "Domain Posture" + "Brand Threat."** The old
  category mixed two subjects: *your own domain's health* and *external
  impersonation threats*. Now `domain_security`, `domain_probe`, `dns_history`
  form **Domain Posture** (your DNS/email/RDAP health), and `typosquat` +
  `asn_cluster` form **Brand Threat** (lookalike domains + coordinated
  phishing-infra clusters). Split by subject (a tool-clean cut — no rewrites);
  execution phases unchanged. 8 → 9 phase groups. Display-only `phase_group` change.
- **Split the exposure findings out of Asset Discovery into a new "Asset
  Exposure" category.** `takeover_check` (subdomain takeover) and `cloud_assets`
  (open cloud buckets) are *findings about exposed assets*, not discovery — so
  they now group under **Asset Exposure** (phase 5), leaving **Asset Discovery**
  (phases 3–4) as pure discovery: `subfinder`, `amass`, `alterx`, `asn_discovery`,
  `dnsx`. Execution order is unchanged (both still run at phase 5); display-only
  `phase_group` change. Also refreshed the stale phase-group table in DESIGN.md.
- **Renamed the "Surface Enumeration" tool category to "Asset Discovery."** More
  accurate and standard: the phases-3–5 tools (`subfinder`, `amass`, `alterx`,
  `asn_discovery`, `dnsx`, `takeover_check`, `cloud_assets`) discover the org's
  external *assets* — subdomains, IP ranges, cloud storage. Parallels the existing
  "Port Discovery" category and ties to the `asset_inventory` app. Display-only
  `phase_group` rename.

### Removed
- **Retired the `github_recon` tool.** The GitHub Org Recon tool (infra references —
  internal hostnames/subdomains, cloud-bucket URLs, API endpoints — in the org's
  public GitHub repos) is removed: app, tests, and its Full Scan + Passive Scan
  workflow steps (migration 0033 cleans existing DBs on deploy). Registry tool
  count 30 → 29. The secret-scanning GitHub tool (`github_secrets`) and infra
  discovery via subdomains/ASN remain.

### Changed
- **`js_secrets` moved to the Web Exposure category.** It runs at phase 12 (it
  needs discovered `.js` assets), so it now groups with its execution neighbors
  (`nuclei`/`web_checker`) instead of Credential Exposure. This makes **Credential
  Exposure a clean, single-phase (phase 2) category** — `breach_check`,
  `hudson_rock`, `github_secrets`. Display-only `phase_group` change; `js_secrets`
  still finds and redacts hardcoded secrets, unchanged.

## [v2.14.2] — 2026-09-11

### Changed
- **Faster releases — stop building the images twice.** On a release (main/tag
  push) the `docker` CI job built both images and then `publish` rebuilt+pushed
  them again, in series. `docker` is now **PR-only** (its role is the required
  build gate on PRs, where it also warms the `type=gha` cache); on main/tag pushes
  it's skipped and `publish` is the sole builder, reusing that cache. Removes a
  redundant full worker build from the release critical path (~2–4 min/release).
  No change to what ships or to the PR gate.

## [v2.14.1] — 2026-09-11

### Changed
- **Deterministic prod image pinning + a documented verify→promote flow.** The k8s
  Deployments now use **bare image names**; the version is pinned in one place —
  `k8s/kustomization.yaml` `images[].newTag` (bumped from a stale `v2.1.1` to the
  current release) — with `imagePullPolicy: IfNotPresent`. Promotion is now a
  deliberate, reversible act (bump `newTag` → apply; rollback = set it back),
  instead of the non-deterministic `:latest` the Deployment fields previously
  named. `docker-compose.dev.yml` takes an `OPENEASD_TAG` (default `latest`) so
  `just deploy-dev` can **smoke-test the exact release image** before promoting —
  closing the "native dev ≠ shipped artifact" gap. Full playbook added to
  `docs/DEVELOPMENT.md` ("Ship it — verify in dev, then promote to prod").

## [v2.14.0] — 2026-09-11

### Changed
- **Renamed the "Data Leak" tool category to "Credential Exposure."** More
  accurate and better-parallel with the sibling "…Exposure" categories: the four
  tools (`hudson_rock`, `breach_check`, `github_secrets`, `js_secrets`) surface
  exposed *credentials and secrets* (infostealer logs, breached accounts, leaked
  API keys/tokens), not general "data leaks." Display-only `phase_group` rename.
- **Pipeline renumbered to 13 phases — Credential Exposure is now a dedicated phase 2.**
  The three domain-only Credential Exposure tools (`hudson_rock`, `breach_check`,
  `github_secrets`) moved from phase 1 into their own **phase 2**, and every phase
  at or after the old phase 2 shifted **+1** (Surface Enumeration 2→3 … cve_intel
  12→13). `js_secrets` stays in the web-exposure phase (now 12) — it needs
  discovered `.js` assets, so it can't run early; the Credential Exposure
  *category* still spans phases 2 and 12. Execution order and all data dependencies are unchanged
  (the shift preserves relative ordering); only phase numbers changed. Phase
  numbers live in each tool's `tool_meta` (no migration). Docs + the generated
  `render_pipeline_diagram` reflect the new numbering.

## [v2.13.0] — 2026-09-11

### Added
- **Lookalike ASN clustering — new `asn_cluster` tool.** Turns isolated
  typosquat findings into a *campaign* signal: it reads the registered
  `lookalike_domain` findings, resolves their IPs to autonomous systems via Team
  Cymru's keyless DNS service, and groups lookalikes that share an ASN into a
  single `lookalike_cluster` finding ("6 lookalikes all resolve into AS-NNNNN —
  coordinated phishing infrastructure; take them down together"). A cluster with a
  weaponized member (login form / brand impersonation, as flagged by typosquat) is
  **high**, else **medium**; a lone lookalike per ASN raises nothing. **Passive**
  (queries Team Cymru, never the target or the lookalikes), fail-graceful,
  `requires: [typosquat]`, phase 12 (runs after typosquat's findings exist). Joins
  Full Scan + Passive Scan (migration 0032); registry tool count 29 → 30. This is
  the target-scoped slice of adversary-infrastructure correlation — it clusters
  *your* lookalikes, not the whole internet.
- **Deeper email-authentication checks in `domain_security`.** Beyond present/absent
  SPF/DMARC, the phase-1 passive check now catches the gaps that actually let mail
  be spoofed or silently unprotected:
  - **SPF:** neutral `?all` and *no* `all` mechanism (both = no protection); and the
    **RFC 7208 ten-DNS-lookup limit** — over 10 lookups SPF returns permerror and is
    silently ignored (**high**), with a **near-limit** warning at 8–10 (nested
    includes can tip it over).
  - **DMARC:** subdomain policy `sp=none` under an enforcing `p=` (subdomains left
    spoofable), partial enforcement `pct<100`, and missing `rua=` (no reporting
    visibility).
  - **Bug fix:** the old DMARC check used `"p=none" in record`, which substring-matches
    `sp=none` — a `p=reject; sp=none` record was mis-reported as `p=none`. Now parsed
    by tag. Passive, no new tool. Fast mocked tests in `test_domain_security_email.py`.

## [v2.12.0] — 2026-09-10

### Changed
- **Faster phase-1 (Domain Intelligence) — concurrency where it was serial.** Two
  changes cut the phase from up-to-minutes toward seconds:
  - `typosquat` now resolves its lookalike candidates and probes their homepages
    **concurrently** (bounded thread pools, `TYPOSQUAT_DNS_CONCURRENCY`=16 /
    `TYPOSQUAT_FETCH_CONCURRENCY`=8) instead of one-at-a-time — it was the phase's
    dominant cost (up to 300 serial DNS lookups + 25 serial 6s homepage fetches).
    Results stay deterministic (candidate order preserved) and fail-graceful.
  - The workflow runner now **parallelises a phase group of only light,
    network-I/O tools even under `LOW_MEMORY`** (`_LOW_MEM_PARALLEL_SAFE` —
    domain_security/domain_probe/typosquat/dns_history/hudson_rock/breach_check/
    github_secrets; override via `SCAN_LOW_MEM_PARALLEL_SAFE`). Previously low
    memory serialised *every* multi-tool phase; now only groups containing a
    RAM-hungry scanner (nuclei/amass/…) stay serial, so the phase-1 intelligence
    group runs concurrently on a 1GB box without risking an OOM. **Why:** the
    low-memory rule exists to avoid two memory hogs at once — it needlessly
    serialised the cheap DNS/HTTP intelligence tools too.

### Added
- **`render_pipeline_diagram` management command — a generated, drift-proof
  pipeline diagram.** Renders the whole scan pipeline (every phase group, tool,
  passive/active classification, and dependency) straight from the tool registry
  as self-contained HTML (`-o file.html`), a terminal tree (`--format text`), or
  JSON (`--format json`). **Why:** a hand-drawn diagram silently goes stale the
  moment a tool moves; this reads `AppConfig.tool_meta` live, so it always matches
  the code, and it stamps the build version + git sha + render time so a reader
  can tell how current it is. A drift-guard test asserts every registered tool
  appears in the output. Passive/active is colour-coded to the `DomainAuthorization`
  boundary (green = passive, amber = active).

### Changed
- **Split `domain_security` into a passive tool + a new active `domain_probe`.**
  `domain_security` bundled passive lookups (DNS/DNSSEC/CAA/email-auth via public
  resolvers, RDAP via rdap.org) with three checks that touch the target directly
  (AXFR zone transfer against its nameservers, an SMTP open-relay probe against
  its MX, and the MTA-STS policy-file fetch). Because of those three it was
  classified **active** and could never run in a no-auth passive scan — so a
  passive scan got *no* DNS/email intelligence at all. The active probes moved to
  a new **`domain_probe`** tool (active, requires `DomainAuthorization`), leaving
  `domain_security` **passive**. Now: the Passive Scan workflow includes
  `domain_security` (DNS/DNSSEC/SPF/DMARC/DKIM/RDAP with no authorization), and
  `domain_probe` joins the Full Scan (migration 0031). Registry tool count 28 → 29.
  `domain_security` findings keep `source="domain_security"` (historical
  continuity); the moved findings now carry `source="domain_probe"` with their
  check_types unchanged (`dns`/`open_relay`/`email`), so CWE/report mappings still
  resolve. The "Can someone spoof our email?" report question matches both sources.

### Added
- **Per-finding "Recommended Next Steps" on hosted reports.** The PDF report's
  finding detail now carries a concrete, ordered remediation checklist per finding
  type (e.g. HSTS → confirm HTTPS → add the header → submit to hstspreload.org),
  on top of the existing Remediation prose. Covers the common web-header / cookie
  / CORS / disclosure / security.txt / email-auth / TLS / SSH / takeover /
  cloud-bucket / exposed-secret findings; unmapped types render nothing (no empty
  block). **Gated on hosted reports only** — it renders when `REPORT_CTA_URL` is
  configured (the same flag that marks a hosted deployment); self-hosters still
  get the per-finding Remediation text. **Why:** turns "what's wrong" into "what
  to do next," in copy-pasteable steps, for the reader who has to action the
  report. Report-only — no scanning, model, or API change.
- **security.txt (RFC 9116) responsible-disclosure check.** `web_checker` now
  checks whether the scan's **primary domain** publishes a `security.txt` at
  `/.well-known/security.txt` — the standard, machine-readable way a researcher
  finds out how to report a vulnerability. Absent → **info** finding; present but
  **expired** (`Expires:` in the past) → **low**; present and current → nothing.
  **Why:** a missing or lapsed disclosure contact quietly delays every inbound
  vulnerability report. Scoped to the apex/www origin only (the policy is
  domain-root, per the RFC) so it fires at most once per scan instead of once per
  subdomain, and a 200 that's really an SPA catch-all HTML page is rejected (must
  carry a `Contact:` line, must not be HTML) so it never reports a false positive.
  Cert validation stays on for this fetch (a security.txt over an untrusted cert
  isn't trustworthy); a TLS/connection failure is treated as "couldn't check" and
  reports nothing, never a false "missing". Folded into the existing `web_checker`
  tool — no new registration, tool-count, or Full-Scan change. Fail-graceful (a
  fetch error is logged, never raised).
- **"Since Your Last Scan" report block + alert line.** The PDF report now opens
  (right under the Exposure Score) with what changed versus the domain's previous
  scan — **N new / N resolved / N still-open** findings, plus a list of the new
  issues (investigate first) and the resolved ones. The findings CSV gains a
  **"New This Scan"** column flagging the same new issues, and Slack/Teams alerts
  carry a **"N new since the last scan"** line/fact. **Why:** a point-in-time
  snapshot doesn't answer the first question a returning reader asks — *"what's
  different since last time?"*. The diff reuses the existing `ScanDelta` identity
  key (`source:check_type:title`), picks the same non-subscan baseline as delta
  detection, and respects the report's `min_severity` filter + hidden-title
  suppression. Absent on a domain's first scan (no baseline), and the alert
  line/fact is omitted when nothing is new, so those payloads stay byte-identical.

### Changed
- **New "Data Leak" tool category.** The four tools that surface *leaked
  credentials/secrets* rather than *domain posture* — `hudson_rock` (infostealer
  logs), `breach_check` (breach exposure), `github_secrets` (secrets in public
  GitHub), and `js_secrets` (secrets in fetched JS) — now group under a dedicated
  `phase_group: "Data Leak"` instead of being mixed into "Domain Intelligence"
  (the first three) and "Web Exposure" (`js_secrets`). **Why:** Domain
  Intelligence had drifted into a catch-all; splitting leak-detection into its own
  category makes the scan-start category picker, the report groupings, and the
  "Did we leak keys / were staff logins stolen?" CEO questions line up with a
  single, clearly-named bucket. Display-only regrouping — execution order
  (`phase`), runners, and findings are unchanged.

### Added
- **DKIM selector inference from MX/SPF.** DKIM selectors are per-provider and
  not discoverable from the domain, so the old check tried only a fixed common
  list. It now fingerprints the mail provider from MX and SPF records (Google
  Workspace, Microsoft 365, Zoho, Amazon SES, SendGrid, Mailchimp, Fastmail,
  Proofpoint) and checks that provider's known selectors first. This confirms
  DKIM in more cases, and when it still can't, the "DKIM could not be confirmed"
  finding names the detected provider and records the selectors checked — so a
  missing record reads as more likely genuine.

### Removed
- **Dead `apps/domain_security/checks/` package** (`email.py`, `dns.py`,
  `rdap.py`, `__init__.py`). Their `collect_and_analyze` functions were imported
  nowhere — the live domain-security logic is all in `scanner.py`. This is the
  shadow that caused an earlier report-copy fix to land in dead code (the
  duplicate email checks); removing it prevents a repeat.

## [v2.11.0] — 2026-09-10

### Changed
- **Trimmed the buyer-facing report (roadmap Delete/hide bucket).** These are
  still stored and shown in the app — just removed from the exported PDF/CSV:
  - **BIMI not configured** and **Domain update lock not enabled** findings are
    suppressed from the report (marketing / lowest-value noise).
  - **RDAP lookup failed** is no longer a finding in the report — it's surfaced
    as a "Registration Data Unavailable" **coverage caveat** instead (the lookup
    didn't fail *security*, it just couldn't be completed).
  - **dns_history** and **github_secrets** are hidden from the report's Scope &
    Methodology when unconfigured (no DNS-history URL / no GitHub token) — so the
    report never implies a check that couldn't run. (Also keeps the "Did we leak
    keys?" question honest when github_secrets is inert.)

### Added
- **"The Five Questions" executive block in the PDF report.** The report now
  opens (in the Executive Summary) by answering the five questions a
  decision-maker actually asks — Can someone spoof our email? · Can we lose our
  domain? · Are staff logins stolen? · Is anyone impersonating us? · Did we leak
  keys? — each mapped to the relevant findings with a status: at risk (a
  critical/high), needs attention (medium/low), no issues found, or **not
  assessed** (the tool that answers it wasn't in this scan — an honest state, not
  a false all-clear).

### Changed
- **Domain Intelligence finding tuning (report roadmap, Edit bucket).**
  - **DNSSEC** ("not enabled" and "chain of trust broken") and **MTA-STS** ("not
    configured") dropped from **high → medium** — real hygiene gaps, but not
    directly exploitable at high. (The DNSSEC "DS published but DNSKEY missing"
    case stays high — it causes actual resolution failure.)
  - **DKIM** finding reworded "DKIM record not found" → **"DKIM could not be
    confirmed"** — DKIM uses a per-provider selector that can't always be
    discovered, so absence at common selectors is a lookup limitation, not proof.

### Fixed
- **Email report copy now actually renders (completes the v2.10.x fix).** The
  earlier per-control business-impact fix stamped `extra["control"]` in a
  **dead** module (`checks/email.py`), while the live email checks live in
  `scanner.py::_check_email` — so real email findings carried no `control` and
  the copy still didn't render. Stamped the live path (spf/dmarc/dkim/mta_sts/
  tls_rpt/bimi), with a regression test. (`checks/{email,dns,rdap}.py`
  `collect_and_analyze` are dead code — flagged for a follow-up removal.)

### Added
- **typosquat now scores weaponization, not just registration.** For registered
  lookalikes that serve web (have an A record), it fetches the homepage
  (capped, short-timeout, fail-graceful) and looks for a **login form**
  (credential phishing) and **brand mentions** (impersonation). A lookalike with
  either signal is now **high** severity ("active impersonation — prioritise a
  takedown"), vs. `medium` for merely-registered and `low` for parked. This
  distinguishes a parked name from an active phishing site, making the "lookalike
  → takedown" workflow actionable. Ported from the standalone `tldsquatting`
  project's threat model. Still passive w.r.t. the target (contacts only the
  lookalike domain, never yours); `extra` now carries `login_form` /
  `brand_mentioned` / `content_checked`.

## [v2.10.1] — 2026-09-10

### Fixed
- **SPA entry point is no longer cacheable (stale UI after deploy).** After
  v2.10.0, prod still showed the old UI (Assets/Findings nav) because Cloudflare
  had cached `index.html` (`max-age=3600`), so browsers loaded the previous
  content-hashed JS bundle while the backend was already new. The SPA catch-all
  now serves `index.html` with `Cache-Control: no-store` so the mutable entry
  point always revalidates; content-hashed `/static/` assets keep their long
  cache. Same class of fix as `/health` (which already set `no-store` after
  Cloudflare cached `/api/version`). **Note:** a CDN that ignores origin
  Cache-Control still needs its cache rule adjusted to bypass the HTML document,
  and a one-time cache purge to clear the currently-stale copy.

## [v2.10.0] — 2026-09-10

### Changed
- **The UI is now strictly scan-centric.** The scan is the single organizing
  unit: the global Findings page and the persistent Assets inventory pages
  (list + detail) were removed, along with their nav entries and routes.
  Findings and assets are viewed only within a scan (Scan Detail's tabs).
  Finding triage (status: open/acknowledged/in_progress/resolved/false_positive)
  moved into the Scan Detail finding modal, so no capability was lost. The
  Dashboard's cross-scan cards (Domain Intelligence, Asset inventory) were
  dropped; the domain-status table (→ View Scans) and latest-scan KPIs remain.
  **Why:** commit to the scan as the primary model rather than the prior
  half scan / half attack-surface-posture UI. The `/api/assets/` endpoints and
  `asset_inventory` data layer are left intact (valid REST surface, still tested).

### Added
- **Domain Intelligence surfaced as the primary scan category.** The category
  taxonomy (phase_group) — previously an internal execution-ordering concept —
  is now first-class in the UI: the Workflows tool picker is grouped by category
  (Domain Intelligence first), and `/api/workflows/tools/` exposes `phase_group`
  and `active` per tool.
- **Scan-start presets with dynamic attestation.** The Start Scan form offers
  three intent-based presets — Passive recon / Full scan / Custom. The
  authorization attestation now appears only when the selection includes active
  tools or is scheduled (matching the API's auth gate), so passive scans are
  friction-free and Passive is the default. `/api/workflows/` exposes
  `is_passive` per workflow.
- **Category-scoped scans.** Under the Custom preset, a By category / By workflow
  toggle lets you launch a scan restricted to selected categories' tools without
  building a workflow. `/api/scans/start/` accepts an optional validated `tools`
  subset, gated on `is_passive_tool_set` and run via `subscan_tools`.

## [v2.9.1] — 2026-09-10

### Changed
- **Pinned Django to the 5.2 LTS line.** The dependency was `django>=5.2.17`, an
  open lower bound that floated to the latest release — so on Python ≥3.12 it
  resolved to **Django 6.1 (non-LTS)**, and the web + worker images had silently
  been running 6.1. Changed the constraint to `django>=5.2.17,<6.0` so it stays on
  the **5.2 LTS** line (security-supported into ~2028) and never jumps to a non-LTS
  6.x by accident. `uv.lock` re-resolved 6.1 → 5.2.17. **Why:** LTS gives a long,
  predictable security-support window — the same conservative-stability reasoning
  behind pinning Python to 3.12. Moving to the next Django LTS (6.2) becomes a
  deliberate bump, not a silent float. Full suite re-verified on 5.2.17.
- **Standardized on Python 3.12 across every tier.** The web image and CI had
  drifted onto Python 3.14 (a `python:3.14-slim` web base + `setup-python: 3.14`)
  while the worker ran Ubuntu 24.04's Python 3.12 — so CI tested a Python the
  production scanner tier never ran, and vice-versa. Pinned everything to 3.12:
  web image `python:3.14-slim` → `python:3.12-slim`, CI `setup-python` 3.14 →
  3.12, `requires-python` `>=3.11` → `>=3.12`, `.python-version` 3.11 → 3.12
  (local dev), and the `refresh-backports` workflow 3.11 → 3.12. **Why:** one
  interpreter across dev, CI, web, and worker removes version skew — CI now
  exercises the exact Python that ships in both prod images. 3.12 is the mature,
  fully-wheel-supported choice already validated on the worker. `uv.lock`
  refreshed (drops the 3.11-only resolution branch).

## [v2.9.0] — 2026-09-10

### Added
- **In-app finding detail view.** Clicking a finding title now opens a detail
  modal with the full **description**, **remediation**, and **vulnerability
  intelligence** (CVE / CVSS / EPSS / CISA-KEV, pulled from the finding's
  `extra`). Wired into both places findings are listed — the Findings page and
  the Scan Detail findings tab — with titles rendered as clickable buttons.
  **Why:** that detail already existed (it fills the PDF report) but was
  unreachable in the app; you previously had to export CSV/PDF to see *why* a
  finding matters or *how* to fix it. Frontend-only — the finding rows already
  carry the full object, so the modal renders with no extra fetch. Built on the
  existing `AlertDialog` primitive (Escape/backdrop close), with unit tests.

## [v2.8.0] — 2026-09-10

### Added
- **Exposure Score surfaced in the UI (Dashboard + Insights).** The backend
  already computed a per-scan Exposure Score (0–100, graded A–F) and returned it
  on `/api/insights/` (`exposure` block) and `/api/dashboard/` (per-domain
  `exposure_score`/`exposure_grade`), but the app never rendered it — it only
  appeared in the PDF report. Added a shared `Exposure` component and wired it in:
  a hero card on Insights (score, grade, trend vs. last scan) and an **Exposure**
  column on the Dashboard Domain Status table. **Why:** it's the single best
  at-a-glance risk metric; hiding it in the PDF wasted data the API already
  provided. Frontend-only, no backend change. Trend is inverted on purpose —
  higher exposure is worse, so an upward move renders red ("more exposure").

### Fixed
- **Reports page listed no scans.** `ReportsPage.jsx` read the paginated scans
  response as `data.scans`, but the `/api/scans/` envelope keys the list under
  `results` (as `ScansPage` already does), so the Reports page always showed
  "No completed scans" and CSV/PDF export was unreachable from it. Read
  `data.results`.

### Security
- **weasyprint 69.0 → 70.0 (CVE-2026-55073).** pip-audit (the CI CVE gate)
  flagged a newly-disclosed vulnerability in weasyprint 69.0 — the PDF report
  renderer. Raised the floor to `weasyprint>=70` and refreshed `uv.lock` to the
  fixed 70.0. PDF export verified unaffected; the report tests mock the renderer
  so behaviour is unchanged.

## [v2.7.0] — 2026-09-09

### Fixed
- **Vite config `__dirname` warning.** `vite.config.js` used the CJS `__dirname`
  global, which Vite 8's native config loader warns is unsupported; switched to
  `import.meta.dirname` (supported on the Node ≥20.19 Vite 8 requires). Dev-only.

### Added
- **Dedicated Reports page** (`/reports`, new nav item). Lists completed scans
  with per-scan **CSV/PDF export** and a `min_severity` filter, so you can export
  without opening each scan (the Scan Detail export buttons stay too). Frontend-only
  — reuses the existing `/reports/<uuid>/{csv,pdf}/` endpoints; the SPA `/reports`
  route coexists with them via Django's SPA catch-all and a `^/reports/.+` Vite
  dev-proxy regex.

## [v2.6.0] — 2026-09-09

### Fixed
- **asn_discovery test robust to `TOOL_AMASS` path.** `test_happy_path_two_step`
  pinned the amass command's binary to the bare `"amass"`; any environment that
  sets `TOOL_AMASS` to an absolute path (Docker/k8s deployments, or a local `.env`
  for running scans) failed the test though the code was correct. Now asserts the
  binary ends with `amass` and checks the args separately.

### Added
- **Dev deployment via `just` (production stays on the GitHub pipeline).** Clean
  split: the **dev** lifecycle lives in `just` — `just setup`, `just dev` (hot
  reload), `just up` (build+run the 3-container stack locally), and new
  **`just deploy-dev`** (run the CI-published `:latest` images via
  `docker-compose.dev.yml`, no local build). **Production is unchanged** — still
  `git tag vX.Y.Z` → the GitHub pipeline builds & publishes pinned `:vX.Y.Z`
  images to GHCR; `just` is not used for prod.
- **`justfile` task runner** (alongside the existing `Makefile`) with matching
  recipes plus extras: **`just ci`** runs the full CI pipeline locally (ruff +
  pytest w/ 80% coverage gate + bandit + pip-audit + vitest + build, mirroring
  `.github/workflows/ci.yml`), and `just up`/`down`/`logs`/`ps` drive the
  3-container Docker Compose stack. `just` with no argument lists all recipes.

## [v2.5.0] — 2026-09-09

### Changed
- **Web image on Python 3.14; CI tests on 3.14.** The `web` runtime image moves
  `python:3.12-slim` → `python:3.14-slim`, and the CI test job moves 3.12 → 3.14
  so the shipped web Python is the tested one. Verified: the full dependency set
  installs on 3.14 (CI Docker Build + a local 3.14 venv — django/psycopg/lxml/
  cryptography/weasyprint/dbos/pydantic all import) and the suite passes on 3.14.
  The `worker` image stays Ubuntu 24.04 (Python 3.12) — an intentional split, the
  worker base is pinned to the OS the scanner tools were validated on;
  `requires-python >=3.11` covers both. Supersedes Dependabot PR #346.

## [v2.4.2] — 2026-09-09

### Changed
- **Settings split into a `settings/` package.** `openeasd/settings.py` is now
  `openeasd/settings/` (`base.py` + `__init__.py`) — the standard, more-scalable
  Django layout, so environment-specific overrides can layer on `base.py` if ever
  needed. `DJANGO_SETTINGS_MODULE=openeasd.settings` is unchanged (resolves to the
  package); behaviour is identical (no config values changed, full suite green).
  Structural only — no user-facing change.

## [v2.4.1] — 2026-09-09

### Fixed
- **Subdomain-takeover false positives suppressed via a live HTTP probe** — a
  dangling-DNS candidate is only reported when the probe confirms it, cutting
  noise from stale-but-harmless records (contributor fix).

### Changed
- **Dependency bumps:** worker base image `debian` 12-slim → 13-slim; dev deps
  `postcss` 8.5.26 → 8.5.28 and `autoprefixer` 10.5.4 → 10.5.5; CI action
  `peter-evans/create-pull-request` pinned to a newer SHA.
- **Frontend test-tooling major upgrades (coordinated).** `vitest` 4→5,
  `@vitest/ui` 4→5, and `@testing-library/jest-dom` 6→7, bumped together (vitest
  and its UI must share a major). Dev-only; no product code. All 22 Vitest tests
  pass and the bundle builds unchanged — no source edits needed. Supersedes the
  separate Dependabot PRs #351/#349/#352.

### Fixed
- **Graceful timeout handling for `asn_discovery` and `dnsx`.** `asn_discovery`
  now catches `ToolTimeout` from `amass intel` and returns no findings instead of
  failing the step (ASN/CIDR discovery is informational, so a slow BGP/registry
  lookup should not flip a scan to `partial`); `dnsx`'s subprocess timeout is
  raised 300s→600s so large subdomain sets resolve fully. Re-applied from a
  contributor PR with the import path corrected for the core-app layer reorg
  (`apps.core.engine.workflows.exceptions`) + a regression test.

## [v2.4.0] — 2026-09-09

### Added
- **UI-managed BYOK credentials — foundation (C1).** New
  `apps/core/console/credentials` app: a `ToolCredentials` encrypted singleton
  (Fernet at rest) + a `get_credential()` resolver (**DB value wins over env**,
  env fallback, fail-graceful) + a **write-only** `/api/credentials/` (presence
  booleans + a `db|env|none` source per key; values never returned). **Why:** so
  tool API keys (Shodan/HIBP/GitHub/DNS-history) can be set from the UI without a
  redeploy, reusing the existing at-rest crypto. Additive — no tool is wired to
  the resolver yet (that's C3), so scans are unchanged. Bootstrap secrets
  (`FIELD_ENCRYPTION_KEY`, `SECRET_KEY`, `DB_*`) deliberately stay env-only. Spec:
  `docs/specs/2026-09-09-credential-management.md`.
- **UI-managed BYOK credentials — tools wired (C3).** `shodan`, `breach_check`,
  `github_recon`, `github_secrets`, and `dns_history` now read their key via
  `get_credential()` instead of `settings` directly, so a key stored in the DB
  (`ToolCredentials`) **overrides the env var with no redeploy**; an unset DB key
  falls back to env exactly as before. Existing tool tests unchanged (env fallback
  preserves them); a new test proves a DB key drives `shodan` onto the paid host
  tier with no env key. Cloudflare still defers to `AISettings`. **Why:** this is
  where UI/DB keys start taking effect. Next: the CredentialsPage UI (C5).
- **UI-managed BYOK credentials — the Credentials page (C5).** A new
  **`/credentials`** page (nav item between Notifications and AI Analysis): one
  row per key (Shodan / HIBP / GitHub token+secret / DNS-history) with a
  password input + Save/Clear and a presence/source pill (**Set (UI)** / **From
  env var** / **Not set**). Write-only — values are never displayed; Clear is
  enabled only for keys set in the UI. A footer notes that `SECRET_KEY` /
  `FIELD_ENCRYPTION_KEY` / `DB_*` stay env-only. Completes the credential-management
  feature (C1+C3+C5): manage all tool BYOK keys from the console, no redeploy.

## [v2.3.0] — 2026-09-08

### Changed
- **`@durable_task` engine adapter (PQC hardening H6, slice 1).** New
  `apps/core/engine/durable/task.py` — a thin decorator over DBOS so task bodies
  don't import the engine: `task()` runs the body in-process (testable without a
  DBOS engine), `task.delay()` durably enqueues (with an optional `dedupe`
  template → DBOS `deduplication_id`). The two one-step tasks `ai_triage` and
  `agent_step` are converted; the `enqueue_*` helpers now delegate to `.delay()`.
  `run_scan` stays an explicit multi-step workflow (its per-phase checkpointing is
  the point). Workflow names/dedup unchanged → no behaviour change; DBOS
  construction + registration verified. Principle #11 (keep the engine behind an
  adapter). Plan: `docs/specs/2026-09-07-producer-queue-consumer-hardening.md`.
- **Reorganised the core apps into layer subpackages.** The 15 `apps/core/*` apps
  now live under **`apps/core/console/`** (dashboard, insights, reports,
  notifications, ai, api), **`apps/core/engine/`** (scans, workflows, durable,
  scheduler, service_detection), and **`apps/core/data/`** (domains, assets,
  web_assets, findings, asset_inventory), matching the logical layer model.
  Import paths are now `apps.core.<layer>.<app>`. **Django labels are unchanged**,
  so the database and migrations are untouched (no schema change, no data
  migration). Purely organisational; full test suite green.
- **Removed a vestigial SQLite write-lock from the workflow runner.** `runner.py`
  serialised parallel `WorkflowStepResult` writes behind a `threading.Lock` left
  over from the SQLite era. **Why:** on PostgreSQL concurrent writers are fine
  (each tool thread uses its own connection), and a per-process lock wouldn't
  serialise across worker replicas anyway — so it was needless intra-phase
  contention + misleading comments. Correctness-neutral; restores true parallel
  step-result writes. Also logged the watchdog↔DBOS-resume overlap as **H4** in
  the PQC hardening plan.

### Fixed
- **Alert idempotency on finalize replay (PQC hardening H1).** `_dispatch_alerts`
  now skips re-sending when the session already has a `sent` `Alert` row. **Why:**
  scan finalize is a durable DBOS step that can be *replayed* after a partial crash
  (worker dies after the Slack/Teams webhook POST but before the step checkpoints);
  without the guard, resume re-fired the alerts → duplicate notifications. Only
  `sent` rows count, so a prior attempt that failed entirely is still retried. Plan:
  `docs/specs/2026-09-07-producer-queue-consumer-hardening.md`.

## [v2.2.0] — 2026-09-07

### Added
- **Asset inventory — backend foundation (PR1).** A new `apps/core/asset_inventory`
  layer builds a persistent, deduplicated `Asset` record per unique
  (domain, kind, key) — subdomains/IPs/ports/URLs — with `first_seen`/`last_seen`/
  `status`, populated by a fail-graceful rollup at scan finalize (honest
  `gone`-marking: only on completed scans, only for kinds actually observed).
  `Finding.asset` links findings to the inventory. A backfill migration seeds it
  from existing scan history. **Read API (PR2):** `GET /api/assets/` (paginated,
  filterable by domain/kind/status/search, each row with per-severity open-finding
  counts), `GET /api/assets/summary/` (totals by kind + active/gone), and
  `GET /api/assets/<id>/` (metadata + findings + scan timeline). **Assets UI (PR3):**
  a new **Assets** nav item + inventory page (filter by kind/status/domain, search,
  per-asset severity chips) and an **AssetDetail** page (metadata, findings across
  scans, and the scan-seen timeline) — the asset-centric view of the attack
  surface. **Polish (PR4):** a dashboard "Asset inventory" KPI (active/gone,
  linking to the Assets page), a Finding→Asset cross-link (the findings API now
  carries `asset_id`/`asset_key`/`asset_kind`, and the Findings page links each
  finding to its asset), and README/DESIGN notes. See
  `docs/specs/2026-09-06-asset-centric-inventory.md`. Additive: with the
  inventory unused, scans behave exactly as before.
- **Historical DNS Records tool (`dns_history`, tool #28) — passive.** Queries a
  passive-DNS dataset for a domain's historical A/AAAA/MX records and surfaces
  each as an informational finding (past hosting / stale records → recon and
  occasional takeover leads). Passive (queries a third-party dataset, never the
  target → no authorization needed); BYO endpoint via `DNS_HISTORY_API_URL`
  (no-op when unset); fail-graceful (never fails a scan). Joins the default Full
  Scan and the Passive Scan workflow.

### Changed
- **k8s: web and worker are now separate Deployments** (`web-deployment.yaml` +
  `worker-deployment.yaml`) instead of one pod with two containers — a default
  deploy is now 3 pods (web, worker, postgres). This lets the DBOS worker scale
  independently (`kubectl scale deploy/openeasd-worker --replicas=N`, all draining
  the same queue), keeps `NET_RAW` off the internet-facing web tier, and allows
  independent rollouts. The web Deployment's initContainer runs migrations; the
  worker waits via the role-aware entrypoint (`OPENEASD_ROLE=worker`). Logs go to
  **stdout** (the `ReadWriteOnce` logs PVC is removed, so nothing blocks a rolling
  update), and the Service selector pins `tier: web`. **Why:** matches the
  recommended 3-tier topology and delivers the independent-scaling benefit the
  single-pod layout couldn't.

## [v2.1.1] — 2026-09-06

### Fixed
- **k8s deploy pointed at a non-existent image tag.** `k8s/kustomization.yaml`
  pinned `openeasd-web`/`-worker` to `v0.4` — a pre-split tag that was never
  published for the split images (those start at v2.0.0), so a fresh
  `kubectl apply -k k8s/` would `ImagePullBackOff`. Pinned to `v2.1.1`. (The
  v2.1.0 release tag shipped the broken `v0.4` pin because this fix landed on
  `main` just after that tag was cut — v2.1.1 is the corrected release.)
- **k8s probe host dropped from the secret's `ALLOWED_HOSTS`.** The kubelet
  readiness/liveness probes send `Host: openeasd.local`, and the secret's
  `ALLOWED_HOSTS` overrides the configmap's — so a `secret.yaml` filled in with
  only the real host made Django 400 the probes and the pod never went Ready.
  The `secret.yaml` template now keeps `openeasd.local` in `ALLOWED_HOSTS`, and
  CLAUDE.md spells out the override + probe-host requirement.

### Removed
- **Duplicate/stale docs.** Dropped the root `PRD.md` — a diverged duplicate of
  the canonical `docs/PRD.md` whose "Delivered" section duplicated the CHANGELOG
  and whose "Planned" roadmap was mostly shipped or now contradicts the
  single-user design. Also removed `docs/LOCAL_BRANCH_DBOS.md`, an unreferenced
  status doc for the long-since-merged DBOS branch, and the two historical
  `docs/specs/2026-06-01-cloud-assets-*.md` implementation specs for a shipped
  feature (unreferenced). `docs/PRD.md` is the single canonical PRD; the WAF
  coverage spec (still referenced from CLAUDE.md + settings) stays.
- **Dead SQLite WAL signal handler** in settings — a leftover `connection_created`
  hook that only fired for the SQLite backend, which no longer exists (Postgres
  since v2.0). No behavior change.

## [v2.1.0] — 2026-09-06

### Removed
- **Dead `main.py` dev-runner.** It launched `manage.py qcluster` (Django-Q2,
  removed in the v2.0 DBOS re-platform) and was only `COPY`d into the image, never
  executed (the entrypoint is `docker-entrypoint.sh`). The canonical dev runner is
  `make dev`; README updated to point there. Also dropped a stale README reference
  to a non-existent `src/hooks/` directory and an unused test import.

### Security
- **Login brute-force rate limiting.** After `LOGIN_RATELIMIT_MAX_FAILURES`
  (default 5) failed logins from an IP within a window, that IP is locked out of
  `POST /api/token/pair` (429 + `Retry-After`) for the lockout period. Backed by
  a `LoginThrottle` DB model so the limit holds across gunicorn workers; only the
  credential endpoint is limited (not refresh), and a successful login resets the
  counter. Per-IP keying is **per-IP, not per-username** (per-username would let
  an attacker lock the admin out — an account-lockout DoS). The client IP comes
  from `X-Forwarded-For` when `LOGIN_RATELIMIT_TRUST_FORWARDED_FOR` is on (the
  default, correct behind the mandated TLS reverse proxy); set it `False` for a
  bare deployment, where XFF is attacker-spoofable and the unspoofable
  `REMOTE_ADDR` is used instead so the limit can't be evaded by rotating the
  header. All thresholds are tunable via `LOGIN_RATELIMIT_*` env. **Why:** a
  single-admin app exposes exactly one login to guess — an unthrottled one is a
  standing brute-force target.
- **BYOK secrets encrypted at rest.** API keys, tokens, and webhook URLs stored
  in the database — the Cloudflare AI token, Slack/Teams webhook URLs, and every
  provider key on the amass/subfinder config models — are now Fernet-encrypted
  via a transparent `EncryptedField` (`apps/core/crypto.py` + `fields.py`). The
  key is derived from `SECRET_KEY` by default, or set `FIELD_ENCRYPTION_KEY` to
  decouple it. Existing plaintext rows are migrated in place and read
  tolerantly. **Why:** a database dump or backup previously exposed the
  operator's third-party credentials in cleartext.

### Developer experience
- **CI now enforces `ruff` lint, a frontend test suite (Vitest + Testing
  Library), and an 80% backend coverage floor** — all three were previously
  uncovered (ruff/black/isort and pytest-cov were installed but never run; the
  React SPA had no tests). **Why:** catch regressions mechanically instead of in
  review.

## [v2.0.0] — 2026-09-06

### Added
- **AI analysis layer (`apps/core/ai`) — triage, adaptive orchestration, and
  summaries via Cloudflare Workers AI (BYOK).** After each scan it ranks
  findings by exploitability with a per-finding rationale ("Fix These First"
  panel on scan detail + "Analyst Summary" block in the PDF), can schedule
  bounded follow-up subscans based on what was found (hard caps on iterations
  and subscans; active tools re-checked against `DomainAuthorization` at the
  agent's own dispatch boundary), and writes plain-language report/alert
  summaries (one extra Slack block / Teams fact when present). Entirely off
  unless Cloudflare credentials are provided (saved on the /ai page, or
  `CLOUDFLARE_ACCOUNT_ID` + `CLOUDFLARE_API_TOKEN` env vars as fallback) AND the
  operator enables it AND records consent (first-use dialog); with the gate
  closed every scan runs byte-identical to before. Every call is recorded in
  an audit log (time, scan, purpose, model, token counts, finding IDs — the
  audit model has no text fields, so prompt/response bodies are structurally
  unpersistable). New `/ai` page (settings, consent, connection test, call
  log) and `/api/ai/` router. **Why:** v2.0 direction per D-009/D-014/D-015 —
  the differentiation is being smarter about scanner output than the tools we
  wrap; scanner-grade output is commodity, analyst-grade output is not.
  Supersedes the Ollama/Claude design of D-010–D-012 (see DECISIONS.md).
- **GitHub Org Recon tool (`github_recon`, tool #25) — passive.** Enumerates the
  target org's PUBLIC GitHub repos via GitHub's official REST API and surfaces
  exposed infrastructure references in that public code/config: internal
  hostnames/subdomains of the target domain, cloud-storage bucket URLs
  (S3/Azure/GCP), and API endpoints. Emits one `info` summary Finding ("N public
  repos discovered for org X") plus one `low` `github_infra_exposure` Finding per
  unique reference (deduped, capped at 200), naming the repo + file it came from.
  Two-tier BYO-token: unauthenticated works keyless at GitHub's 60 req/hr public
  limit (we cap total requests + repos to stay under it), a `GITHUB_TOKEN` raises
  the ceiling to 5000 req/hr. Passive (`active=False`) — it queries GitHub, never
  the target, so it needs no `DomainAuthorization` and joins both the Full Scan and
  the no-auth Passive Scan (migration 0027). Fail-graceful throughout: any
  API/network/JSON error or rate-limit returns empty and never fails a scan.
  - **Why:** an org's public source is part of its external attack surface, and
    developers routinely commit internal hostnames, bucket names, and API base URLs
    into public repos, READMEs, and CI config — recon an attacker would otherwise
    have to earn. This widens the discovered surface *from source*, complementing
    the secret-focused `js_secrets`/`github_secrets` tools (this one finds infra
    exposure, not secrets — and never stores secrets).
  - **Hypothesis (user-driven):** the highest-signal, lowest-noise GitHub recon for
    a defender is "which of our own infrastructure did we accidentally publish,"
    surfaced as aggregate low/info findings rather than a raw grep dump.
  - **Provenance/ToS:** uses ONLY GitHub's official REST API (no scraping), sends
    the honest OpenEASD User-Agent, and honours GitHub's documented rate limits
    (403/429 + `X-RateLimit-*`) with capped backoff. `GITHUB_TOKEN`/`GITHUB_ORG` are
    per-deployment secrets, never baked into the image.

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

<!-- Version compare links (Keep a Changelog) -->
[Unreleased]: https://github.com/cybersecify/OpenEASD/compare/v2.15.1...HEAD
[v2.15.1]: https://github.com/cybersecify/OpenEASD/compare/v2.15.0...v2.15.1
[v2.15.0]: https://github.com/cybersecify/OpenEASD/compare/v2.14.2...v2.15.0
[v2.14.2]: https://github.com/cybersecify/OpenEASD/compare/v2.14.1...v2.14.2
[v2.14.1]: https://github.com/cybersecify/OpenEASD/compare/v2.14.0...v2.14.1
[v2.14.0]: https://github.com/cybersecify/OpenEASD/compare/v2.13.0...v2.14.0
[v2.13.0]: https://github.com/cybersecify/OpenEASD/compare/v2.12.0...v2.13.0
[v2.12.0]: https://github.com/cybersecify/OpenEASD/compare/v2.11.0...v2.12.0
[v2.11.0]: https://github.com/cybersecify/OpenEASD/compare/v2.10.1...v2.11.0
[v2.10.1]: https://github.com/cybersecify/OpenEASD/compare/v2.10.0...v2.10.1
[v2.10.0]: https://github.com/cybersecify/OpenEASD/compare/v2.9.1...v2.10.0
[v2.9.1]: https://github.com/cybersecify/OpenEASD/compare/v2.9.0...v2.9.1
[v2.9.0]: https://github.com/cybersecify/OpenEASD/compare/v2.8.0...v2.9.0
[v2.8.0]: https://github.com/cybersecify/OpenEASD/compare/v2.7.0...v2.8.0
[v2.7.0]: https://github.com/cybersecify/OpenEASD/compare/v2.6.0...v2.7.0
[v2.6.0]: https://github.com/cybersecify/OpenEASD/compare/v2.5.0...v2.6.0
[v2.5.0]: https://github.com/cybersecify/OpenEASD/compare/v2.4.2...v2.5.0
[v2.4.2]: https://github.com/cybersecify/OpenEASD/compare/v2.4.1...v2.4.2
[v2.4.1]: https://github.com/cybersecify/OpenEASD/compare/v2.4.0...v2.4.1
[v2.4.0]: https://github.com/cybersecify/OpenEASD/compare/v2.3.0...v2.4.0
[v2.3.0]: https://github.com/cybersecify/OpenEASD/compare/v2.2.0...v2.3.0
[v2.2.0]: https://github.com/cybersecify/OpenEASD/compare/v2.1.1...v2.2.0
[v2.1.1]: https://github.com/cybersecify/OpenEASD/compare/v2.1.0...v2.1.1
[v2.1.0]: https://github.com/cybersecify/OpenEASD/compare/v2.0.0...v2.1.0
[v2.0.0]: https://github.com/cybersecify/OpenEASD/compare/v0.10.0...v2.0.0
[v0.10.0]: https://github.com/cybersecify/OpenEASD/compare/v0.9.0...v0.10.0
[v0.9.0]: https://github.com/cybersecify/OpenEASD/compare/v0.8.0...v0.9.0
[v0.8.0]: https://github.com/cybersecify/OpenEASD/compare/v0.7.1...v0.8.0
[v0.7.1]: https://github.com/cybersecify/OpenEASD/compare/v0.7...v0.7.1
[v0.7]: https://github.com/cybersecify/OpenEASD/compare/v0.6...v0.7
[v0.5]: https://github.com/cybersecify/OpenEASD/compare/v0.4...v0.5
