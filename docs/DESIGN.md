# OpenEASD — Architecture & Design

> **Audience:** engineers. For product requirements see [PRD.md](PRD.md).
> For engineering decisions see [DECISIONS.md](DECISIONS.md).
> **`CLAUDE.md` (repo root) is the authoritative, exhaustive reference** —
> full tool/endpoint/test tables live there. This doc is the standalone
> architecture overview; where it abbreviates, CLAUDE.md is the source of truth.

---

## System Overview

```
Browser (React 19 SPA)
       │  JWT Bearer (Authorization: Bearer …)
       ▼
web tier — gunicorn (python:3.12-slim image, no scanner tools)
  ├── Django Ninja REST API  (/api/)   + login rate-limit middleware
  ├── WhiteNoise             (frontend/dist/, static/)
  ├── Django Admin           (/admin/)
  └── enqueue-only: durably enqueues scans onto the DBOS queue
       │  Django ORM                         │  DBOSClient.enqueue
       ▼                                     ▼
PostgreSQL 17  ◄──────────────────  worker tier — dbos_worker (ubuntu:24.04 image,
  app rows (ORM) + DBOS checkpoints        full scanner matrix, NET_RAW)
  (a `dbos` schema in the same DB)     ├── run_scan_workflow   (@DBOS.workflow; phases = checkpointed @DBOS.step)
                                       ├── ai_triage / agent_step workflows
                                       └── @DBOS.scheduled crons (daily scan, sweeps, watchdog, JWT purge)
```

Three tiers, each its own container/workload: **db** (`postgres:17-alpine`),
**web** (UI/API + synchronous CSV/PDF reports; no tools, no `NET_RAW`), **worker**
(DBOS durable execution + the scanner binaries; `NET_RAW`). The web tier only
*enqueues* scans; the worker *executes* them. Scans are **durable DBOS workflows**
whose phase groups are checkpointed steps, so a crashed/restarted worker
**resumes** a scan instead of losing it. PostgreSQL holds all shared state (app
data + DBOS checkpoints); there is no SQLite and no Django-Q/APScheduler.

---

## Layers vs. Tiers — two orthogonal axes

OpenEASD is best understood as **4 logical layers** deployed as a **3-tier
topology**. These are *different axes* — code is organized by layer, runtime is
organized by process — and they deliberately do **not** map 1:1. Keep them
separate: a folder can't "live in the web container," because both containers
import the same codebase and differ only by entrypoint.

### Axis 1 — logical layers (how the CODE is organized, by responsibility)

```
┌─ CONSOLE   presentation: Ninja API + React SPA + reports/insights/notifications/ai
│               apps/core/{dashboard, api, insights, reports, notifications, ai}
├─ ENGINE    orchestration: durable scan execution + dynamic workflow runner
│               apps/core/{scans, workflows, durable, scheduler}
├─ TOOLS     plugins: the 27 self-registering scanner tools
│               apps/<tool>/  (subfinder, nmap, nuclei, …)
└─ DATA      models: the dataflow substrate every layer reads/writes
                apps/core/{domains, assets, web_assets, findings, asset_inventory}

Dependency direction — everything points DOWN to DATA (which depends on nothing):
      console ─┐
      engine  ─┼──►  data
      tools   ─┘
```

The current folders don't *nest* these layers (it's `apps/core/*` + flat
`apps/<tool>/*`), but every app maps cleanly to exactly one layer — see the
Core Infrastructure and Tool Apps tables below.

### Axis 2 — deployment tiers (how the RUNTIME is organized, by process)

```
   client ──HTTPS──►  web (gunicorn)  ──enqueue via DBOS queue──►  worker (dbos_worker)
                      python:slim                                   ubuntu:24.04
                      console code paths                            engine + tools code paths
                      no tools, no NET_RAW                          full scanner matrix, NET_RAW
                              └──────────────► db (postgres:17-alpine) ◄──────────────┘
                                               app data + DBOS checkpoints
```

### The map between them (layer → container)

| Logical layer | Runs in | Note |
|---|---|---|
| **Console** | `web` | gunicorn serves the API + React bundle |
| **Engine** | `worker` | `dbos_worker` runs the durable scan workflows |
| **Tools** | `worker` | the scanner binaries live only in the worker image |
| **Data** | `db` | Postgres; accessed by **both** web & worker via the Django ORM |

**Why the mismatch is correct:** it's **one codebase, two entrypoints** — the
`web` and `worker` images ship the same Python code and differ only in which
process they start (`gunicorn` vs `dbos_worker`). So folders are grouped by
*layer* (responsibility), never by *container* (process). This keeps deployment
flexible — a layer can be re-mapped to a different container without moving any
code — and keeps the internet-facing `web` image tool-free regardless of how the
code is organized. **Decision:** the 4-layer model lives here as documentation;
the folders stay a standard `apps/core/*` + flat `apps/<tool>/*` Django layout and
are **not** reorganized to mirror the layers — a reorg would be pure churn (every
import path, the 27 `tool_meta` runner strings, tests) with no functional gain.
Reorganize only if the flat layout starts causing real friction.

---

## Core Infrastructure — `apps/core/`

The core apps are physically grouped into **layer subpackages** —
`apps/core/console/`, `apps/core/engine/`, `apps/core/data/` — matching the
logical layers (see the *By layer* table below). Django labels are unchanged, so
the folder move is purely organisational; the table lists each app by name.

| App | Django label | Responsibility |
|---|---|---|
| `dashboard/` | `core` | Dashboard KPIs; `UserProfile` (`must_change_password`); `LoginThrottle` (brute-force limiter) |
| `domains/` | `domains` | `Domain`, CRUD, activate/deactivate, monitoring config, `DomainAuthorization` |
| `assets/` | `assets` | Network assets: `Subdomain`, `IPAddress`, `Port` |
| `web_assets/` | `web_assets` | Web assets: `URL` |
| `service_detection/` | `service_detection` | Enriches `Port.service` + `Port.is_web` via nmap -sV |
| `findings/` | `findings` | Unified `Finding` model — all finding-producing tools write here |
| `asset_inventory/` | `asset_inventory` | Persistent, deduplicated `Asset` inventory (domain-scoped, first/last-seen + status); populated by a fail-graceful rollup at finalize; `Finding.asset` links findings to it; `/api/assets/` + the Assets UI |
| `scans/` | `scans` | `ScanSession`, `ScanDelta`, `ScheduledScan`, pipeline orchestrator |
| `workflows/` | `workflow` | Workflow CRUD, dynamic runner, tool registry |
| `scheduler/` | `scheduler` | Scan callables (daily/monitoring/user sweeps, watchdog, JWT purge) invoked by the DBOS `@scheduled` workflows |
| `durable/` | `durable` | DBOS app config + `@DBOS.workflow`/`@DBOS.step`/`@DBOS.scheduled` definitions; `dbos_worker` command |
| `notifications/` | `alerts` | `NotificationConfig` singleton, Slack/Teams dispatcher, alert history |
| `insights/` | `insights` | `ScanSummary` (incl. Exposure Score + grade), `FindingTypeSummary`, trend charts |
| `reports/` | `reports` | CSV + PDF export (synchronous Django views, on the web tier) |
| `ai/` | `ai` | AI triage / adaptive orchestration / summaries (Cloudflare Workers AI, BYOK) — a core subsystem, **not** a registry tool |
| `api/` | — | `NinjaAPI` instance, JWT routes, router registration, error handlers, rate-limit middleware |

### By layer — console / engine / data

The 15 core apps map cleanly to three of the four logical layers (see
[Layers vs. Tiers](#layers-vs-tiers--two-orthogonal-axes)):

| Layer | Apps | Count |
|---|---|---|
| **Console** (presentation) | `dashboard`, `insights`, `reports`, `notifications`, `ai` | **5** |
| **Engine** (orchestration) | `scans`, `workflows`, `durable`, `scheduler` | **4** |
| **Data** (dataflow models) | `domains`, `assets`, `web_assets`, `findings`, `asset_inventory` | **5** |
| *(core + registry tool)* | `service_detection` — a core app that is *also* a phase-6 scan tool | **1** |

**Total: 15 core apps.** The `api/` module is part of the console tier but is
**not** a registered app (no models — it only mounts routers), so it's not in the
15. The fourth logical layer, **Tools**, is the 27 `apps/<tool>/` plugins (next
section) — bringing the first-party total to 42 apps / 28 registered tools
(`service_detection` is the one app counted in both core and the tool registry).

Notes on the mapping's soft edges:
- **`scheduler`** sits in *engine* as its **automated-operations** sub-part (cron
  triggers + hygiene). Under the producer→queue→consumer lens it's a *producer*,
  not the execution core — the one app where the two lenses disagree on placement.
- **`service_detection`** is the only app that is both core infrastructure and a
  registry tool (nmap -sV, phase 6).

Secrets at rest (`apps/core/crypto.py` + `fields.py`): BYOK API keys and webhook
URLs stored in the DB are Fernet-encrypted via `EncryptedCharField`/`EncryptedTextField`.

---

## Tool Apps — `apps/<tool>/`

Tools are **self-registering**: each `AppConfig` declares `tool_meta` and the
registry (`apps/core/engine/workflows/registry.py`) auto-discovers them at startup.
Adding a tool needs only an `INSTALLED_APPS` entry + a data migration to join the
default Full Scan — no core files change.

```
apps/<tool>/
    apps.py       — AppConfig with tool_meta (label, runner, phase, phase_group, requires, produces_findings, active)
    models.py     — empty (data goes to apps/core/data/assets|web_assets|findings)
    scanner.py    — thin orchestrator: collect → analyze → save
    collector.py  — runs binary / probes; returns raw data (no DB writes)
    analyzer.py   — parses raw data; builds Asset / Finding objects
```

**28 registered tools.** Each carries an `active` flag: **passive** tools use only
public/third-party data (no packets to the target → no authorization needed);
**active** tools probe the target directly (require a `DomainAuthorization`). The
full per-tool table is in [CLAUDE.md](../CLAUDE.md); by phase group:

| Phase group | Phases | Tools |
|---|---|---|
| Domain Intelligence | 1 | domain_security, hudson_rock, dns_history, github_secrets, typosquat, breach_check |
| Surface Enumeration | 2–4 | subfinder, amass, asn_discovery, alterx, github_recon, dnsx, takeover_check, cloud_assets |
| Port Discovery | 5–6 | naabu, shodan, service_detection |
| Network Exposure | 7 | nmap, tls_checker, ssh_checker, nuclei_network |
| Web Exposure | 8–11 | httpx, historical_urls, katana, nuclei, web_checker, js_secrets |
| Prioritization | 12 | cve_intel (enriches CVEs with EPSS + CISA-KEV in place) |

Binaries: ProjectDiscovery tools (`subfinder`/`dnsx`/`naabu`/`httpx`/`katana`/
`nuclei`) + `amass`, `gitleaks`, `subzy`, `gau` are pinned static binaries;
`nmap` is the one distro package. All live only in the **worker** image.

---

## Scan Pipeline

### Asset data model

```
Domain
  └── Subdomain  (source: seed | subfinder | amass | alterx | dnsx)
        └── IPAddress  (public only; private/loopback/link-local/AWS-metadata filtered)
              └── Port  (is_web=True|False set by service_detection)
                    └── URL  (from httpx; SNI-matched)
```

Deletion cascades top-down: deleting a Domain wipes all session data.

### Pipeline phases

```
Phase 1   Domain Intelligence  → Finding (DNS/email/RDAP, breach, typosquat, infostealer, public-secret)
Phase 2   Surface Enumeration  → Subdomain (subfinder/amass/alterx) + Finding (asn_discovery, github_recon)
Phase 3   dnsx                 → IPAddress (public-IP filter)
Phase 4   takeover / cloud     → Finding (dangling DNS, open buckets)
Phase 5   naabu / shodan       → Port + Finding (passive exposure)
Phase 6   service_detection    → enriches Port.service + Port.is_web
Phase 7   Network Exposure     → Finding (nmap CVE / tls / ssh / nuclei_network — non-web; run in parallel)
Phase 8-10 httpx → historical_urls → katana → URL (web probing / archived / crawl)
Phase 11  Web Exposure         → Finding (nuclei web, web_checker headers, js_secrets)
Phase 12  cve_intel            → enriches CVE findings with EPSS + CISA-KEV (no new findings)
```

### Scan flow (call chain)

```
POST /api/scans/start/  (authorization gate: active tools need DomainAuthorization;
  │                       a "now" scan of ONLY passive tools may bypass it)
  → create_scan_session(domain)        # ScanSession; auto-assigns the default Full Scan workflow
    → run_scan_task(session_id)        # DURABLY ENQUEUES onto the DBOS "scans" queue (DBOSClient)
        (worker picks it up)
    → run_scan_workflow(session_id)    # @DBOS.workflow
        → mark_session_running
        → prepare_session_assets       # Python-side DNS resolution of the apex
        → for group in phase_groups:   #   each phase group = a checkpointed @DBOS.step (→ resumable)
              run_phase_group_for_session
        → finalize_session_by_id       # count findings → deltas → coverage → insights → AI → alerts → status
```

`_finalize_session` order: build deltas → coverage/WAF regression → `build_insights`
(Exposure Score) → asset-inventory rollup (`rollup_session`, fail-graceful) →
`run_ai_post_scan` (triage + summaries, inline) → `_dispatch_alerts`
(Slack/Teams) → `maybe_start_agent` (queues the bounded AI orchestration chain).

### Scan statuses

| Status | Meaning |
|---|---|
| `pending` | Durably enqueued on the DBOS queue, not yet picked up |
| `running` | The DBOS workflow is executing (resumes across worker restarts) |
| `completed` | All steps finished normally |
| `partial` | Watchdog reaped it, or a tool failed; ≥1 step completed |
| `failed` | No steps completed, or unrecoverable error |
| `cancelled` | Stopped by user via `POST /api/scans/<uuid>/stop/` |

### Key design rules

1. **Tools never import from each other.** Shared data flows through the core
   asset/finding models only.
2. **`Port.is_web`** is the classification gate — set by `service_detection`
   (Phase 6); nmap skips web ports, nuclei_network targets non-web, tls_checker
   probes all.
3. **httpx feeds subdomain:port pairs, not IP:port** — needed so SNI matches on
   CDN/Cloudflare-fronted hosts.
4. **dnsx filters to public IPs** — private/loopback/link-local/AWS-metadata IPs
   dropped before any port scanning.
5. **Delta detection** compares all findings of the current completed scan against
   the previous completed scan for the same domain; subscans are excluded from the
   "previous scan" lookup.
6. **Duplicate-scan protection** is the `uniq_active_scan_per_domain` partial unique
   constraint + an if-active check (Postgres); `service_detection` (active nmap -sV)
   is auto-injected only when `naabu` is in the run.

---

## Workflow vs. Pipeline — the two paradigms (hybrid, by design)

A scan uses **both**: it runs a **workflow** (which tools) **through the pipeline**
(what order + how data flows). They are two paradigms operating at two layers, and
they meet in exactly one function — `resolve_phase_groups()` in
`apps/core/engine/workflows/runner.py`, which takes the workflow's tool *set* and imposes
the pipeline's phase *order*.

| | **Workflow-centric** | **Pipeline-centric** |
|---|---|---|
| Controls | *which* tools run | *what order* + *how data flows* |
| The unit | `Workflow` + `WorkflowStep` (DB rows) | fixed 12 phases + dataflow models |
| Mutable? | ✅ dynamic — user-configurable | ❌ fixed — hardcoded `tool_meta["phase"]` |
| Lives in | `apps/core/engine/workflows/` (models, api, runner, registry) | `tool_meta` phases + `apps/core/engine/scans/pipeline.py` |
| Example control | enable/disable tools; Full / Passive / custom workflows | `dnsx`(3)→`naabu`(5)→`httpx`(8): IPs before ports before web probing |

A workflow can enable/disable tools and set their *intra-phase* `order`, but can
**never** move a tool to a different phase or reorder the phases — the phase
sequence encodes hard dataflow dependencies, so its fixity is correctness
enforcement, not a limitation.

### Pros / cons of each paradigm

**Workflow-centric** — *Pros:* flexibility (compose custom scans), reusable presets
(Full/Passive), zero-code tool extensibility, scan *modes* fall out naturally
(passive vs active → the authorization boundary), user control without a deploy.
*Cons:* indirection ("what will this scan run?" is runtime DB state, not readable in
one file), more machinery (registry + runner + config models), a
*registered-but-not-scanned* seam (a tool joins Full Scan only via a data migration),
bigger test surface.

**Pipeline-centric** — *Pros:* predictable, readable dataflow; strong per-stage
contracts; tools stay decoupled (shared models, fixed phases); easy to debug
(deterministic order); few failure modes. *Cons:* rigidity (can't customize which
stages run without code), no user configurability, awkward for optional/conditional
stages, all-or-nothing.

### Why the hybrid is correct here

The two paradigms constrain **different axes**: the workflow controls the axis you
*want* flexible (which tools), the pipeline controls the axis that *must not* be
flexible (phase order / dataflow — a Port must come from an IP). So the hybrid takes
the pros of both and pays only the mild cons:

- Pure pipeline-centric → too rigid (no passive-only recon, no custom subsets → you'd
  fork the pipeline per mode).
- Pure workflow-centric (reorderable phases) → dangerous (lets port-scan run before
  subdomain discovery → broken dataflow, lost decoupling).

**Decision: keep the hybrid** — workflow-centric orchestration over a
pipeline-centric dataflow. Do not collapse toward either pure form. The one
workflow-centric weakness (the *registered ≠ scanned* seam) is contained by guardrail
tests (`test_default_workflow`, `test_passive_scan`) and could be further tightened
by a `"default_scan"` flag in `tool_meta` (optional; see the hardening backlog).

---

## Unified Finding Model

Finding-producing tools write to `apps/core/data/findings/Finding`:

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
  extra        JSON  # tool-specific: cvss_score, epss_score, cisa_kev, cipher_name, …
```

> **Portability note:** the codebase groups JSON-extracted fields
> (`extra__cvss_score`) in Python rather than via DB `Max(...)` aggregation — a
> habit from the former SQLite backend. PostgreSQL supports these natively; the
> Python-side grouping is kept for portability and needn't be "fixed".

---

## REST API

Base path: `/api/`. Auth: JWT Bearer via `ninja-jwt` (simplejwt).

### Auth flow

```
POST /api/token/pair      → {access, refresh}   # login (per-IP brute-force rate-limited)
POST /api/token/refresh   → {access}             # renew
POST /api/token/blacklist                         # logout (blacklists refresh token)
```

Access token sent as `Authorization: Bearer <token>` on every request; the React
axios interceptor silently refreshes on 401. Tokens live in `localStorage`
(`auth.js`). Login is rate-limited by `LoginRateLimitMiddleware` (per-IP,
DB-backed `LoginThrottle`).

### Response format

```json
{"id": 1, "domain": "example.com", ...}              // success — flat, no envelope
{"error": {"code": "NOT_FOUND", "message": "..."}}   // error
```

### Key endpoints (abbreviated — full list in CLAUDE.md)

```
GET  /api/dashboard/                  KPIs, domain status (incl. exposure_score/grade), urgent findings
POST /api/domains/<pk>/authorize/     grant DomainAuthorization (attestation)
POST /api/scans/start/                start or schedule a scan
GET  /api/scans/<uuid>/status/        lightweight status (React polls every 3s while running)
POST /api/scans/<uuid>/subscan/       re-run a subset of tools against an existing scan
GET  /api/scans/findings/             paginated findings (?severity= &domain= &status= &source=)
GET  /api/insights/                   trends, top hosts, asset growth, Exposure Score
GET  /api/assets/                     persistent asset inventory (?domain= &kind= &status= &q=)
GET  /api/ai/triage/<uuid>/           AI triage status + ranked items + agent decisions
GET  /api/version/  /health/          build provenance (unauthenticated)
GET  /api/docs                        OpenAPI / Swagger UI
```

Full URL layout: [CLAUDE.md](../CLAUDE.md#url-layout). CSV/PDF reports are
synchronous Django views under `/reports/<uuid>/` served by the web tier.

---

## AI subsystem — `apps/core/console/ai/`

A core subsystem (not a registry tool) that runs post-finalize over the whole
session. Gated by consent + Cloudflare Workers AI keys (BYOK) — **entirely off
unless configured**, and with the gate closed scans are byte-identical to pre-AI.
As DBOS workflows: **triage** (ranks findings by exploitability — CVSS + EPSS +
CISA-KEV), **summaries** (report/alert text), and a **bounded agent** (one LLM
decision per chained `agent_step` workflow; can launch follow-up subscans,
re-checked against `DomainAuthorization` at its dispatch boundary; hard caps on
iterations/subscans). Every call writes an `AIInvocation` audit row — metadata
only (the model has no text field, so prompt/response bodies are unpersistable).

---

## Frontend Architecture

```
frontend/
  src/
    api/client.js          apiGet(path) / apiPost(path, body) over axiosInstance.js
    api/axiosInstance.js    request interceptor adds Bearer; response interceptor refreshes on 401
    auth.js                localStorage helpers (getToken, setTokens, clear, isLoggedIn)
    router.jsx             react-router-dom createBrowserRouter tree; ProtectedRoute gate
    main.jsx               <RouterProvider> + <QueryClientProvider> + <Toaster>
    lib/queryClient.js     @tanstack/react-query client
    pages/                 one file per route
    components/
      ui/                  shadcn primitives (Button, Card, Table, Badge, …)
      Badge.jsx / Spinner.jsx / Pagination.jsx / ConfirmButton.jsx / Notification.jsx
      BuildInfo.jsx        sidebar build/version footer + "update available" check
      ai/                  ConsentDialog.jsx, TriagePanel.jsx
```

**Tech:** React 19, Vite 8, react-router-dom, @tanstack/react-query, shadcn/ui,
Tailwind CSS 3, Radix UI. Data fetching is `useQuery({queryKey:[path,…]})` +
`apiGet`; live scan status polls at 3s. Tests: Vitest + Testing Library.

**Theme:** dark — `bg #0d1117`, card `#161b22`, border `#30363d`, accent `#30c074`.

**Dev:** Vite proxy forwards `/api/` → Django `:8001` (no CORS). **Prod:**
`npm run build` → `frontend/dist/` → served by WhiteNoise; Django catch-all serves
`index.html` for non-API paths.

---

## Deployment Topologies

The recommended topology is **3 tiers** — the web image carries no offensive
tooling or `NET_RAW`, tool OOMs isolate to the worker, and the worker scales
independently. See CLAUDE.md for the full rationale + pros/cons.

### Docker Compose (recommended)

```
db      postgres:17-alpine          — app data + the DBOS `dbos` schema
web     openeasd-web (slim)         — gunicorn; UI/API + PDF reports; enqueue-only; no tools
worker  openeasd-worker (ubuntu)    — dbos_worker + full scanner matrix; --cap-add NET_RAW
```

The entrypoint is role-aware (`OPENEASD_ROLE`): both roles wait for Postgres; the
web/init role migrates + collectstatic + admin-setup, the worker role waits for
`migrate --check` then launches (no DDL race).

### Kubernetes

Separate Deployments per tier (`kubectl apply -k k8s/`): **`openeasd-web`**
(init migrates → gunicorn; `tier: web`; no `NET_RAW`; the Service targets
`tier: web`), **`openeasd-worker`** (`dbos_worker`; `tier: worker`; `NET_RAW`; no
Service; scale with `kubectl scale deploy/openeasd-worker --replicas=N` on the
same DBOS queue), and a **PostgreSQL StatefulSet**. A default deploy is 3 pods.
Logs go to stdout (no PVC). Readiness/liveness: `GET /health/` (unauthenticated) —
the probe `Host` header must be an entry in `openeasd-secret`'s `ALLOWED_HOSTS`.

---

## Scheduler

Unattended scanning is a set of DBOS `@scheduled` cron workflows registered when
the `dbos_worker` process imports `apps/core/engine/durable/workflows` (never in gunicorn
workers). They call the thin callables in `apps/core/engine/scheduler/scheduler.py`.
`SCHEDULED_SCANS_ENABLED` (default True) is the master switch; the
consent/`DomainAuthorization` gate applies to scheduled scans too.

| Schedule | Default | Description |
|---|---|---|
| Daily scan | `SCAN_DAILY_HOUR:SCAN_DAILY_MINUTE` (02:00) | Full scan of all authorized active domains |
| Per-domain monitoring | 6h / 12h / 24h / 48h / weekly | Configurable per domain; a DBOS sweep computes due-ness |
| User-schedule sweep | — | Fires `once`/`recurring` user-scheduled scans (`ScheduledScan` rows) |
| Stuck-scan watchdog | Every 15 min | Reaps `running` scans past `SCAN_TIMEOUT_MINUTES` and orphaned `pending` scans past `SCAN_PENDING_TIMEOUT_MINUTES` as `partial`/`failed` |
| JWT token purge | Daily | Clears expired simplejwt `OutstandingToken` rows |
