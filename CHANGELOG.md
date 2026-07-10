# Changelog

All notable changes to OpenEASD are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) with a short
**Why** note on non-obvious changes so reviewers don't have to dig through
commits to recover the reasoning.

## [Unreleased]

### Added

- **CVE Intel tool (`apps/cve_intel`)** — New Phase 12 tool in a new *Prioritization* phase group that enriches existing CVE findings in place with **EPSS** scores (FIRST.org exploitation-probability) and **CISA KEV** flags (known-exploited-in-the-wild), rather than producing new findings (`produces_findings=False`). Reads every session Finding carrying a CVE (both shapes tools write — nmap's `extra["cve"]` string and nuclei's `extra["cve_ids"]` list), runs one CISA KEV lookup (cached 24h) plus one bulk EPSS query, and writes a per-finding rollup back into `extra`: `epss_score`/`epss_percentile` (the max across the finding's CVEs), `cisa_kev` (true if any is actively exploited), `kev_cves`, and a per-CVE `cve_intel` map. Both feeds degrade to empty on any network/parse failure, so a scan never fails because a feed is down. 24 unit tests. **Why:** a scan that returns 55–157 findings is only useful if the operator knows which 3 to fix first. EPSS answers "how likely is this to be exploited" and KEV answers "is it being exploited right now" — together they turn a flat wall of CVEs into a ranked, actionable list. This is the single highest value-per-effort add for the defender audience, and it costs no scan time (pure enrichment on findings that already exist). **Hypothesis:** on a typical infra-heavy target, a small number of the CVE findings will carry a KEV flag or high EPSS, and surfacing those first is what a defender actually acts on. **Evidence:** user-driven — requested directly during the ast.co.rs investigation after a partial scan produced dozens of undifferentiated CVE findings. Resolves [#159](https://github.com/cybersecify/OpenEASD/issues/159) via [#160](https://github.com/cybersecify/OpenEASD/pull/160). Follow-up (not in this change): surfacing EPSS/KEV in the findings table and PDF report with sort/filter.

- **Frontend data layer migration** — Data fetching moved to React Query + axios (#132) and routing to react-router-dom v7 (#129), replacing the hand-rolled `useFetch`/`usePolling` hooks and the popstate router. **Why:** cache invalidation, request dedup, and background refetch were being reimplemented by hand; standard libraries remove that surface area and the associated unmount-leak / refetch-race bug class.

### Fixed

- **Full scans now complete instead of dying at exactly 2 hours** (#157, #158) — The Django-Q2 `Q_CLUSTER` config killed every large scan. `timeout: 3600` (1h) hard-killed the worker mid-scan, then `retry: 7200` re-queued a zombie task at exactly 2h — the `retry` comment claimed it "disables retries" but Django-Q2 disables re-queue via `max_attempts`, which was unset. Fix: add `max_attempts: 1` (the real no-requeue switch), and make the timeout a **derived** value instead of a guess — set above the worst-case sum of per-tool caps (~3.4h, dominated by `nuclei_network`'s 1h cap in Phase 7), landing at 4h. The watchdog `SCAN_TIMEOUT_MINUTES` is raised 90m → 240m to stay ≥ the worker timeout, so it only reaps genuinely orphaned scans (dead worker) and never flips a healthy long-running scan to `partial` mid-run. All three knobs are env-tunable (`Q_TASK_TIMEOUT`, `Q_TASK_RETRY`, `SCAN_TIMEOUT_MINUTES`) with a guard forcing `retry > timeout`, and a regression test (`test_qcluster_config.py`) locks the three invariants against future drift. **Why:** the three timers silently contradicted each other, so no scan whose natural runtime exceeded 1h could ever finish. **Evidence:** data-oriented — every failed `ast.co.rs` scan since late May ran for almost exactly 2h, matching the `retry: 7200` re-queue window rather than any scan-specific cause.

- **nuclei no longer downloads templates from GitHub mid-scan** (#161, #162) — nuclei templates were never baked into the Docker image (the Dockerfile installed only the binary), and the template directory lives on the ephemeral container filesystem — only `/app/data` and `/app/logs` are on PVCs. So the first nuclei scan on every fresh pod (i.e. after every redeploy) tried to download the entire template repo from GitHub *during the scan* and hung. Fix bakes templates at build time (`RUN nuclei -update-templates`) and adds `-disable-update-check` to the scan command so no template/version network activity ever happens at scan time. **Why:** this was the true root cause behind ast.co.rs full scans never finishing — separate from the timeout config above. **Evidence:** data-oriented — reproduced on the prod worker: with templates absent nuclei stalls at `nuclei-templates are not installed, installing...`; session 19's nuclei step ran **236.8 min on just 17 URLs** (every other tool combined took ~15 min) and contributed 0 findings before the watchdog killed it. Resolves [#161](https://github.com/cybersecify/OpenEASD/issues/161).

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
  scans on the openeasd.cybersecify.com instance reproduced this exactly —
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
  second and returned the expected `{"host":"scanme.nmap.org","a":["45.33.32.156"]...}`.
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
  **Why:** the load-bearing test (scan `scanme.nmap.org`, get IPs/ports/URLs)
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
  host (e.g. `scanme.nmap.org`) or any domain with no public subdomains produced
  *only* domain_security DNS findings — every other tool ran with an empty input
  set and reported zero. A real first-run test against `scanme.nmap.org` produced
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
