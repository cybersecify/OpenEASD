# Changelog

All notable changes to OpenEASD are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) with a short
**Why** note on non-obvious changes so reviewers don't have to dig through
commits to recover the reasoning.

## [Unreleased]

### Added

- **Subdomain takeover detection (`apps/takeover_check`)** — New Phase 3.5 tool that runs [subzy](https://github.com/PentestPad/subzy) against discovered subdomains and emits a `high`-severity Finding for each subdomain whose DNS points at an unclaimed third-party resource (S3, GitHub Pages, Heroku, Azure, Fastly, etc.). The tool reads from `Subdomain` records (so it picks up everything subfinder/amass found), invokes `subzy run --targets <file> --output <file> --hide_fails`, and writes to the unified `Finding` model with `extra.service` + `extra.raw` for auditability. Dockerfile adds a cross-compiled `subzy-builder` Go stage (`SUBZY_VERSION=v1.2.1`, `CGO_ENABLED=0`, `-ldflags="-s -w"`) since subzy ships no prebuilt binaries — the runtime image gets only the static binary. **Why:** subdomain takeover is one of the highest-leverage external-recon findings (HTTPS-cert-valid phishing surface + same-eTLD cookie/session theft + SSO breakthrough), it's invisible to defenders until exploited, and it was the largest remaining gap in OpenEASD's external attack-surface coverage — none of the existing 14 tools touch dangling DNS. **Hypothesis:** real engagements + small-team scans against orgs with 5+ years of subdomain history will surface 0-3 takeover findings per scan, all genuinely actionable (verified by manually visiting the subdomain). **Evidence:** speculative on per-scan finding count — depends entirely on the target's DNS hygiene. Data-oriented on the gap-closure claim — `grep -r "takeover\|dangling" apps/` returns no matches before this commit, confirming the category was absent. Tool choice and integration approach informed by closed [PR #82](https://github.com/cybersecify/OpenEASD/pull/82) from [@zeroknowledge0x](https://github.com/zeroknowledge0x); implementation rewritten to match the project's five-file plugin pattern, fix the analyzer field name (`extra` not `extras`), use subzy's actual CLI flags (`--output <file>` for JSON, no `--json` flag exists), and add the missing integration glue (tests, `INSTALLED_APPS`, Dockerfile install, CHANGELOG).

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
