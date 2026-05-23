# Changelog

All notable changes to OpenEASD are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) with a short
**Why** note on non-obvious changes so reviewers don't have to dig through
commits to recover the reasoning.

## [Unreleased]

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
