# CLAUDE.md — OpenEASD Django Project

External Attack Surface Detection platform. Built around a 6-phase scan
pipeline that produces shared assets and unified findings.

## Git workflow
- Solo developer — commit directly to main, no branches or worktrees
- Run `uv run pytest tests/ --ignore=tests/unit/test_domain_security.py` before committing
- Tag before big changes (new libs, refactors, schema changes): `git tag -a v0.x -m "description"`
- If something breaks: `git revert <commit>` or `git reset --hard v0.x` to roll back
- **Versioning:** `0.x` = building/architecture changes, `1.0` = first stable public release
- **Pushing to GitHub (clean history):**
  1. Work locally, commit as often as needed
  2. When stable, squash into one commit: `git reset --soft <last-tag> && git commit -m "v0.x: summary"`
  3. Tag it: `git tag -a v0.x -m "description"`
  4. Push: `git push origin main --tags`

## Commands
- Always use `uv run python` instead of `python` or `python3`
- Always use `uv run manage.py` for Django management commands (e.g. `uv run manage.py check`)
- Always use `uv run pytest` for running tests
- The slow `tests/unit/test_domain_security.py` (41 tests) makes real DNS/RDAP calls — exclude it for fast CI runs:
  `uv run pytest tests/ --ignore=tests/unit/test_domain_security.py`

## Stack
- Django 5+ with plain Django views (no DRF, no Celery, no Redis)
- HTMX — server-driven UI updates (form submits, polling, partial HTML swaps)
- Alpine.js — client-side UI state (modals, dropdowns, tabs, toggles, local form state). Use this for any interactivity that doesn't need a server roundtrip.
- Chart.js — visualizations, loaded via CDN only on pages that need it (e.g. insights), not in `base.html`
- Tailwind CSS via CDN (no build step)
- `threading.Thread` for background scan execution
- `django-apscheduler` for daily automated scans (starts in `DashboardConfig.ready()`)
- SQLite database (dev), configurable via `DB_NAME` env var

### Frontend rules
- Reach for **Alpine.js first** for client-side interactivity (don't write vanilla JS event listeners for show/hide, tabs, modals)
- Use **HTMX** when the server needs to compute/return new HTML
- Load page-specific JS (Chart.js, etc.) inside the page template, not `base.html`

## Scheduler
- Daily scan runs at `SCAN_DAILY_HOUR:SCAN_DAILY_MINUTE` (uses `TIME_ZONE` in settings, default 02:00)
- Configured via env vars: `SCAN_DAILY_HOUR`, `SCAN_DAILY_MINUTE`
- Disable on extra workers via `SCHEDULER_ENABLED=False` (for multi-worker gunicorn)
- Job history visible in Django admin under "Django APScheduler"
- Scheduler code lives in `apps/core/scheduler/scheduler.py`
- Started by `apps/core/dashboard/apps.py` → `DashboardConfig.ready()`
- Guard prevents double-start in dev server (checks `RUN_MAIN` env var)

## External binary tools

ProjectDiscovery tools installed via `pdtm` at `~/.pdtm/go/bin/`:
- `subfinder`, `dnsx`, `naabu`, `httpx`

System binary:
- `nmap` (Homebrew at `/opt/homebrew/bin/nmap`)

Tool paths are configurable via `TOOL_SUBFINDER`, `TOOL_DNSX`, `TOOL_NAABU`, `TOOL_HTTPX`, `TOOL_NMAP` env vars. Defaults to pdtm path.

## Project structure

### Core infrastructure — `apps/core/` namespace (10 sub-apps)

| App | Label | Purpose |
|---|---|---|
| `dashboard/` | `core` | Dashboard, health check, scheduler startup |
| `assets/` | `assets` | Shared asset models (Subdomain, IPAddress, Port, URL, Technology, Certificate) — every tool writes here |
| `findings/` | `findings` | **Unified Finding model** — every tool writes findings here, no per-tool finding models |
| `scans/` | `scans` | ScanSession, ScanDelta, scan orchestrator (`tasks.py`) |
| `domains/` | `domains` | Domain model, CRUD views |
| `workflows/` | `workflow` | Workflow + WorkflowStep models, runner, views |
| `scheduler/` | `scheduler` | APScheduler setup (`get_scheduler`, `start_scheduler`) |
| `notifications/` | `alerts` | Alert model, Slack/Teams dispatcher |
| `insights/` | `insights` | ScanSummary, FindingTypeSummary, builder |
| `reports/` | `reports` | Placeholder for future PDF/CSV export |

**Note on `label`:** Moved apps keep their original `app_label` (e.g. `scans`, `alerts`, `workflow`, `core`) so existing migrations and ForeignKey string references stay valid.

### Tool apps (one per scanner)

| App | Type | Status | Phase |
|---|---|---|---|
| `apps/domain_security/` | Pattern 1 (custom Python) | ✅ Active | 1 |
| `apps/subfinder/` | Pattern 2 (OSS binary) | ✅ Active | 2 |
| `apps/dnsx/` | Pattern 2 (OSS binary) | ✅ Active | 3 |
| `apps/naabu/` | Pattern 2 (OSS binary) | ✅ Active | 4 |
| `apps/httpx/` | Pattern 2 (OSS binary) | ✅ Active | 5 |
| `apps/nmap/` | Pattern 2 (OSS binary) | ✅ Active | 6 |
| `apps/tls_checker/` | Pattern 1 (custom Python, stdlib ssl + cryptography) | ✅ Active | 6 |
| `apps/ssh_checker/` | Pattern 1 (custom Python, paramiko) | ✅ Active | 6 |
| `apps/nuclei/` | Pattern 2 (OSS binary) | ✅ Active | 7 |

To add a new tool, register it in:
1. `settings.INSTALLED_APPS`
2. `apps/core/workflows/models.py` `TOOL_CHOICES` and `TOOL_PHASE`
3. `apps/core/workflows/runner.py` `_TOOL_RUNNERS`
4. `apps/core/findings/models.py` `SOURCE_CHOICES` (if it produces findings)

### Tool app structure (Pattern 2 — OSS binary)
```
apps/<tool>/
    models.py       — empty (writes to apps/core/assets/ and apps/core/findings/)
    scanner.py      — thin orchestrator: collect → analyze → save
    collector.py    — runs binary, returns raw data (no DB)
    analyzer.py     — parses raw data, builds shared Asset/Finding objects
```

### Tool app structure (Pattern 1 — custom Python)
```
apps/domain_security/
    scanner.py      — orchestrator + 28 inline check functions
    checks/         — dead code from a refactor attempt; do not import
        dns.py
        email.py
        rdap.py
```
Note: `domain_security/scanner.py` still has all checks inline because tests
patch private helpers like `apps.domain_security.scanner._resolve`. Do not
move logic into `checks/` without updating the tests' patch targets.

## The 6-phase scan pipeline

```
Phase 1  domain_security  → Finding (source="domain_security", DNS/email/RDAP)
Phase 2  subfinder        → assets.Subdomain (passive subdomain enumeration)
Phase 3  dnsx             → assets.IPAddress (public-only filter, marks Subdomain.is_active)
Phase 4  naabu            → assets.Port (top 100 TCP scan against IPs)
Phase 5  httpx            → assets.URL (probes HTTP/HTTPS via subdomain hostname for CDN support)
Phase 6a nmap NSE vulners → Finding (source="nmap", check_type="cve") on non-web ports only
Phase 6b tls_checker      → Finding (source="tls_checker") on ALL open ports (web + non-web)
Phase 6c ssh_checker      → Finding (source="ssh_checker") on SSH ports (paramiko-based)
Phase 7  nuclei           → Finding (source="nuclei") web vuln scan on all URLs from httpx
```

### Key design rules
1. **Tools never import from each other.** All shared data goes through `apps/core/assets/` and `apps/core/findings/`.
2. **dnsx filters to public IPs only.** Private/loopback/link-local/AWS metadata IPs (169.254.169.254) are dropped.
3. **httpx feeds subdomain:port pairs, not IP:port pairs.** Cloudflare/CDN-fronted services need SNI matching the hostname.
4. **Web vs non-web classification** is in `apps/nmap/scanner.py:_web_pairs_for_session()`. A port is "web" if any URL exists for any IP behind the same hostname (handles 1-hostname → multiple-IPs CDN case).
5. **nmap only scans non-web ports** (those without a matching URL record). Web ports are scanned by nuclei in Phase 7.
6. **tls_checker covers ALL open ports** (both web ports via URL scheme and non-web ports via stdlib ssl probing). Web port TLS is inferred from URL scheme (http/https) — no probing needed. Non-web ports are probed with `ssl.create_default_context()` (direct TLS) or STARTTLS (smtp/imap/pop3/ftp). Inherently insecure services (telnet/rlogin/rsh/rexec) are always flagged without probing. Certificate parsing uses the `cryptography` library via `getpeercert(binary_form=True)` for DER bytes (stdlib `getpeercert()` returns empty dict under `CERT_NONE`). Findings cover: unencrypted service, weak ciphers (RC4, NULL, EXPORT, 3DES/Blowfish, SHA-1, CBC, anon, RSA-KEX), deprecated protocols (TLS 1.0/1.1), cert issues (expired, expiring, self-signed, untrusted CA, weak key RSA<2048/EC<256, DSA deprecated, SHA-1 signature, SAN mismatch, missing SCT), and HSTS missing (HTTPS web ports).
7. **Asset deletion cascades** through Subdomain → IPAddress → Port → URL. Deleting a Domain wipes all session data.
8. **ssh_checker probes SSH ports** (service="ssh" from nmap) via `paramiko.Transport` for host key, algorithms, and auth methods. Uses `_probe_weak_algorithms()` to test each weak algorithm individually against the server. Detects: SSHv1, weak host keys (DSA/short RSA), weak kex/ciphers/MACs, password auth, root login.
9. **nuclei scans web URLs** from httpx (Phase 5) using community templates. Feeds URL.objects as targets, runs binary with `-json -silent`, maps JSONL output to unified Finding (source="nuclei"). Deduplicates by (template_id, matched_at). CVE findings get check_type="cve", others get check_type="web". Old `NucleiFinding` model removed — uses unified Finding.

## Unified Finding model

`apps/core/findings/Finding` replaces per-tool models. All tools write to it:

```python
class Finding(models.Model):
    session     = FK(ScanSession)
    source      = "domain_security" | "nmap" | "tls_checker" | "nuclei"
    check_type  = "dns" | "email" | "rdap" | "cve" | ...
    severity    = "critical" | "high" | "medium" | "low" | "info"
    title       = CharField()
    description = TextField()
    remediation = TextField()
    target      = CharField()  # hostname or address
    subdomain   = FK(Subdomain, null=True)
    ip_address  = FK(IPAddress, null=True)
    port        = FK(Port, null=True)
    url         = FK(URL, null=True)
    extra       = JSONField()  # tool-specific: cve, cvss_score, service, version, etc.
```

Backward-compat `@property` accessors on Finding (`cve`, `cvss_score`, `service`, `version`, `port_number`, `address`) so templates work without `extra__cve` lookups.

**SQLite quirk:** Don't use `Max("extra__cvss_score")` or other aggregations on JSON-extracted fields — Django/SQLite will fail with `the JSON object must be str, bytes or bytearray, not float`. Group in Python after fetching the rows. See `apps/core/insights/views.py` for the pattern.

## URL layout
- `/` → dashboard
- `/health/` → health check
- `/domains/` → domain CRUD
- `/scans/` → scan list
- `/scans/start/` → start new scan (now / once / recurring) — Alpine.js form
- `/scans/<uuid>/` → scan detail with live HTMX polling of severity + asset cards
- `/scans/<uuid>/status/` → HTMX fragment (severity + asset counts, polled every 3s)
- `/scans/findings/` → unified finding list (filters: ?severity= ?session_id= ?domain=)
- `/scans/scheduled/` → scheduled jobs list (one-time + recurring)
- `/workflows/` → workflow list/create/detail
- `/insights/` → trends, charts (Chart.js), tool breakdown, top vulnerable services
- `/admin/` → Django admin

## Tests

| File | Tests | Notes |
|---|---|---|
| `tests/unit/test_alerts.py` | 7 | Slack/Teams dispatcher |
| `tests/unit/test_assets.py` | 13 | Shared asset model constraints, FK chains, cascade delete |
| `tests/unit/test_core.py` | 10 | Dashboard view |
| `tests/unit/test_dnsx.py` | 20 | Public IP filter, analyzer, scanner |
| `tests/unit/test_domain_security.py` | 41 | DNS/email/RDAP — **slow, real network** |
| `tests/unit/test_domains.py` | 15 | Domain CRUD |
| `tests/unit/test_httpx.py` | 11 | JSON parser, host_ip → Port lookup, hostname → Subdomain link |
| `tests/unit/test_insights.py` | 11 | Insights builder + view |
| `tests/unit/test_naabu.py` | 9 | JSON parser, FK to IPAddress |
| `tests/unit/test_nmap.py` | 24 | Severity mapping, vulners XML parser, web/non-web exclusion |
| `tests/unit/test_scans.py` | 55 | ScanSession, scheduling, scan_start views |
| `tests/unit/test_subfinder.py` | 11 | JSON parser, dedup, hostname normalization |
| `tests/unit/test_tls_checker.py` | 77 | Cert parsing (cryptography lib), cipher checks, protocol versions, cert lifecycle, weak keys, SHA-1 sig, SAN mismatch, SCT, untrusted CA, HSTS, collector, scanner |
| `tests/integration/test_scan_flow.py` | 13 | Domain security flow + full pipeline (mocked) + delete cascade |

| `tests/unit/test_ssh_checker.py` | 33 | SSH probe, SSHv1, host key, weak kex/cipher/MAC, password auth, root login, collector, scanner |
| `tests/unit/test_nuclei.py` | 25 | CVE parsing, severity mapping, dedup, URL linking, collector subprocess, scanner |

**Total: 375 tests** (334 fast + 41 slow domain_security)
