# OpenEASD — Architecture & Design

> **Audience:** engineers. For product requirements see [PRD.md](PRD.md).
> For engineering decisions see [DECISIONS.md](DECISIONS.md).

---

## System Overview

```
Browser (React SPA)
       │  JWT Bearer / apiFetch
       ▼
Django (gunicorn)
  ├── Django Ninja REST API  (/api/)
  ├── WhiteNoise             (frontend/dist/, static/)
  └── Django Admin           (/admin/)
       │  ORM
       ▼
SQLite (openeasd-data volume)
       ▲
Django-Q2 worker (qcluster)
  ├── Scan pipeline          (run_scan_task)
  ├── Daily/monitoring scans (django_q.Schedule)
  └── Stuck-scan watchdog    (reap_stuck_scans)
```

Web and worker run as two containers in the same pod (K8s) or as a single
container in Docker. SQLite is the only shared state; the worker writes to
it via the Django ORM.

---

## Core Infrastructure — `apps/core/`

| App | Django label | Responsibility |
|---|---|---|
| `dashboard/` | `core` | Dashboard KPIs; `UserProfile` (`must_change_password` flag) |
| `domains/` | `domains` | Domain model, CRUD, activate/deactivate, monitoring config |
| `assets/` | `assets` | Network assets: `Subdomain`, `IPAddress`, `Port` |
| `web_assets/` | `web_assets` | Web assets: `URL` |
| `service_detection/` | `service_detection` | Enriches `Port.service` + `Port.is_web` via nmap -sV |
| `findings/` | `findings` | Unified `Finding` model — all tools write here |
| `scans/` | `scans` | `ScanSession`, `ScanDelta`, pipeline orchestrator |
| `workflows/` | `workflow` | Workflow CRUD, dynamic runner, tool registry |
| `scheduler/` | `scheduler` | Django-Q2 schedule setup: daily scan, monitoring jobs, watchdog, JWT purge |
| `notifications/` | `alerts` | `NotificationConfig` singleton, Slack/Teams dispatcher, alert history |
| `insights/` | `insights` | `ScanSummary`, `FindingTypeSummary`, trend charts |
| `reports/` | `reports` | CSV + PDF export |
| `api/` | — | `NinjaAPI` instance, JWT routes, router registration, error handlers |

---

## Tool Apps — `apps/<tool>/`

Tools are **self-registering**: each `AppConfig` declares `tool_meta` and
the registry in `apps/core/workflows/registry.py` auto-discovers them at
startup. Adding a new tool requires only an entry in `INSTALLED_APPS` — no
core files change.

### Tool app structure

```
apps/<tool>/
    apps.py       — AppConfig with tool_meta (phase, phase_group, runner, requires, produces_findings)
    models.py     — empty (all data goes to apps/core/assets/ or apps/core/findings/)
    scanner.py    — thin orchestrator: collect → analyze → save
    collector.py  — runs binary / probes; returns raw data (no DB writes)
    analyzer.py   — parses raw data; builds Asset / Finding objects
```

### Registered tools

| App | Phase | Phase Group | Produces findings | Description |
|---|---|---|---|---|
| `apps/domain_security/` | 1 | Domain Intelligence | Yes | DNS, email (SPF/DMARC/DKIM/MTA-STS), RDAP |
| `apps/subfinder/` | 2 | Surface Enumeration | No | Passive subdomain enumeration |
| `apps/amass/` | 2 | Surface Enumeration | No | Active subdomain enumeration |
| `apps/alterx/` | 2 | Surface Enumeration | No | Subdomain permutation from discovered subdomains |
| `apps/dnsx/` | 3 | Surface Enumeration | No | DNS resolution; filters to public IPs |
| `apps/takeover_check/` | 4 | Surface Enumeration | Yes | Subdomain takeover detection via subzy (dangling DNS → unclaimed cloud) |
| `apps/naabu/` | 5 | Port Discovery | No | Port scan (top-100 TCP) |
| `apps/core/service_detection/` | 6 | Port Discovery | No | nmap -sV → `Port.service` + `Port.is_web` |
| `apps/nmap/` | 7 | Network Exposure | Yes | NSE vulners CVE scan (non-web ports) |
| `apps/tls_checker/` | 7 | Network Exposure | Yes | TLS ciphers, protocol versions, cert analysis |
| `apps/ssh_checker/` | 7 | Network Exposure | Yes | SSH config (root login, weak kex/cipher/MAC, SSHv1) |
| `apps/nuclei_network/` | 7 | Network Exposure | Yes | Nuclei network protocol templates (non-web ports) |
| `apps/httpx/` | 8 | Web Exposure | No | Web probing, URL discovery (CDN-aware via SNI) |
| `apps/historical_urls/` | 9 | Web Exposure | No | Historical URL discovery via gau + waybackurls |
| `apps/katana/` | 10 | Web Exposure | No | Deep URL crawl on top of httpx |
| `apps/nuclei/` | 11 | Web Exposure | Yes | Nuclei community web vuln scan |
| `apps/web_checker/` | 11 | Web Exposure | Yes | HTTP security headers, cookies, CORS |

---

## Scan Pipeline

### Asset data model

```
Domain
  └── Subdomain  (source: seed | subfinder | amass | alterx | dnsx)
        └── IPAddress  (public only; private/loopback/AWS metadata filtered)
              └── Port  (is_web=True|False set by service_detection)
                    └── URL  (from httpx; SNI-matched)
```

Deletion cascades top-down: deleting a Domain wipes all session data.

### Pipeline phases

```
── Domain Intelligence ──────────────────────────────────────
Phase 1  domain_security    → Finding (DNS / email / RDAP checks)

── Surface Enumeration ─────────────────────────────────────
Phase 2  subfinder          → Subdomain (passive)
Phase 2  amass              → Subdomain (active)
Phase 2  alterx             → Subdomain (permutation candidates)
Phase 3  dnsx               → IPAddress (public-IP filter)
Phase 4  takeover_check     → Finding (dangling DNS → unclaimed cloud)

── Port Discovery ───────────────────────────────────────────
Phase 5  naabu              → Port (top-100 TCP)
Phase 6  service_detection  → enriches Port.service + Port.is_web

── Network Exposure ─────────────────────────────────────────
Phase 7  nmap               → Finding (CVEs on is_web=False ports)
Phase 7  tls_checker        → Finding (ciphers / cert / protocol on all ports)
Phase 7  ssh_checker        → Finding (SSH config on service="ssh" ports)
Phase 7  nuclei_network     → Finding (network protocol vulns, non-web ports)

── Web Exposure ─────────────────────────────────────────────
Phase 8  httpx              → URL (web probing)
Phase 9  historical_urls    → URL (archived URLs via gau + waybackurls)
Phase 10 katana             → URL (deep crawl)
Phase 11 nuclei             → Finding (web vulns via community templates)
Phase 11 web_checker        → Finding (headers / cookies / CORS)
```

### Scan flow (call chain)

```
POST /api/scans/start/
  → create_scan_session(domain)        # auto-assigns default workflow
    → run_scan_task(session_id)        # Django-Q2 async task
      → run_scan(session_id)           # sets status="running"
        → _seed_apex_into_assets()     # Python-side DNS resolution of apex
        → _run_via_workflow(session)   # creates WorkflowRun, calls run_workflow()
          → run_workflow(run_id)       # loops enabled tools in phase order
        → _finalize_session(session)   # findings count, deltas, insights, alerts
```

### Scan statuses

| Status | Meaning |
|---|---|
| `queued` | Enqueued in Django-Q2, not yet started |
| `running` | Pipeline is executing |
| `completed` | All steps finished normally |
| `partial` | Watchdog reaped the scan; ≥1 step completed before timeout |
| `failed` | No steps completed before timeout, or unrecoverable error |
| `cancelled` | Stopped by user via `POST /api/scans/<uuid>/stop/` |

### Key design rules

1. **Tools never import from each other.** Shared data flows through the core
   asset and finding models only.
2. **`Port.is_web`** is the classification gate — set by `service_detection`
   (Phase 5); used by nmap (skip web), tls_checker (branch behavior),
   nuclei_network (skip web).
3. **httpx uses subdomain:port pairs, not IP:port pairs** — necessary for
   CDN/Cloudflare-fronted hosts where SNI must match.
4. **dnsx filters to public IPs** — private, loopback, link-local, and AWS
   metadata IPs are dropped before any port scanning.
5. **Delta detection** compares all findings from the current completed scan
   against the previous completed scan for the same domain. Subscans are
   excluded from the "previous scan" lookup to avoid spurious delta noise.

---

## Unified Finding Model

All 8 finding-producing tools write to `apps/core/findings/Finding`:

```python
Finding
  session      FK → ScanSession
  source       str   # tool label from tool_meta (e.g. "nmap", "tls_checker")
  check_type   str   # tool-specific slug (e.g. "cve", "weak_cipher", "no_spf")
  severity     enum  # critical | high | medium | low | info
  title        str
  description  text
  remediation  text
  target       str   # hostname or "ip:port"
  port         FK → Port (nullable)
  url          FK → URL (nullable)
  extra        JSON  # tool-specific: cvss_score, cipher_name, cert_expiry, …
```

> **SQLite note:** avoid `Max()` / aggregate functions on JSON-extracted fields
> (`extra__cvss_score`). Group and sort in Python instead.

---

## REST API

Base path: `/api/`. Auth: JWT Bearer via `ninja-jwt` (simplejwt).

### Auth flow

```
POST /api/token/pair      → {access, refresh}   # login
POST /api/token/refresh   → {access}             # renew
POST /api/token/blacklist                         # logout (blacklists refresh token)
```

Access token sent as `Authorization: Bearer <token>` on every request.
Tokens stored in `localStorage` via `auth.js`.

### Response format

```json
{"id": 1, "domain": "example.com", ...}              // success — flat, no envelope
{"error": {"code": "NOT_FOUND", "message": "..."}}   // error
```

### Key endpoints (abbreviated)

```
GET  /api/dashboard/                  KPIs, domain status, urgent findings
GET  /api/domains/                    domain list
POST /api/scans/start/                start or schedule a scan
GET  /api/scans/<uuid>/status/        lightweight status (React polls every 3s)
GET  /api/scans/findings/             paginated findings (?severity= &domain= &session_uuid=)
GET  /api/workflows/                  workflow list
GET  /api/insights/                   trend charts, top hosts, asset growth
GET  /api/docs                        OpenAPI / Swagger UI (always enabled)
```

Full URL layout is in [CLAUDE.md](../CLAUDE.md#url-layout).

---

## Frontend Architecture

```
frontend/
  src/
    api/client.js        apiFetch wrapper — injects Bearer token, handles 401
    auth.js              localStorage helpers (getToken, setTokens, clear, isLoggedIn)
    App.jsx              vanilla popstate router (no react-router)
    main.jsx             React root + <Toaster> mount
    pages/               one file per route
    components/
      ui/                shadcn primitives (Button, Card, Table, Badge, …)
      Badge.jsx          cva severity/status variants
      Spinner.jsx
      Pagination.jsx
      ConfirmButton.jsx  wraps AlertDialog
      Notification.jsx   re-exports sonner toast
```

**Tech:** React 19, Vite 8, shadcn/ui, Tailwind CSS 3, Radix UI.

**Theme:** dark — `bg #0d1117`, card `#161b22`, border `#30363d`, accent `#30c074`.

**Dev:** Vite proxy forwards `/api/` → Django `:8000`. No CORS config needed.

**Prod:** `npm run build` → `frontend/dist/` → served by WhiteNoise. Django
catch-all serves `index.html` for all non-API paths.

---

## Deployment Topologies

### Docker (single container)

```
docker run
  initContainer (entrypoint): migrate → collectstatic → admin user setup
  web:    gunicorn openeasd.wsgi --bind 0.0.0.0:8000 --workers 2
  worker: manage.py qcluster   (same container, second process)
```

### Kubernetes (split pod)

```
Pod: openeasd
  initContainer: init   → migrate + collectstatic + admin setup
  container: web        → gunicorn (no NET_RAW needed)
  container: worker     → manage.py qcluster (NET_RAW capability for nmap)
```

Volumes: `openeasd-data` (SQLite) + `openeasd-logs` — RWO, `replicas: 1`.

Service: ClusterIP `:80 → :8000`. Ingress: nginx (TLS-ready annotations).

Readiness/liveness probe: `GET /health/` (unauthenticated).

---

## Scheduler

`apps/core/scheduler/scheduler.py` — `setup_core_schedules()` called from
`SchedulerConfig.ready()`, but **only when `qcluster` is in `sys.argv`**
(never runs in gunicorn workers).

| Schedule | Default | Description |
|---|---|---|
| Daily scan | `SCAN_DAILY_HOUR:SCAN_DAILY_MINUTE` (02:00) | Full scan of all active domains |
| Per-domain monitoring | 6h / 12h / 24h / 48h / weekly | Configurable per domain; managed by `sync_domain_monitoring_jobs()` |
| Stuck-scan watchdog | Every 15 min | Reaps `running` scans stalled past `SCAN_TIMEOUT_MINUTES` (default 240) and orphaned `pending` scans past `SCAN_PENDING_TIMEOUT_MINUTES` (default 60) as `partial` or `failed` |
| JWT token purge | Daily | Clears expired simplejwt `OutstandingToken` rows |
