# CLAUDE.md — OpenEASD Django Project

External Attack Surface Detection platform. Scans domains for network and
web vulnerabilities using a dynamic workflow engine with auto-registered tools.

## GitHub Flow

**Rule:** Never commit to `main` directly.

**Branch prefixes** (only two):
- `feat/` — new features
- `fix/` — everything else (bugs, deps, config, refactor, docs, cleanup)

**Commit message prefixes** — use the most specific one that fits:

| Prefix | When to use |
|---|---|
| `feat:` | New user-facing feature |
| `fix:` | Bug fix |
| `docs:` | Documentation only (README, CHANGELOG, CONTRIBUTING, CLAUDE.md) |
| `ci:` | GitHub Actions, CI config, Dockerfile, dependabot |
| `chore:` | Deps, tooling, config — no behavior change |
| `test:` | Tests only — no production code change |

Branch prefix maps to commit prefix: `feat/` → `feat:`, `fix/` → any of the above.

### Steps for every task

1. **Sync main:**
```bash
git checkout main && git pull
```
   If `git pull` complains about uncommitted changes or a dirty working tree, stop and investigate before continuing — don't stash blindly, you may have unpushed work from a previous branch.

2. **Create branch:**
```bash
git checkout -b feat/short-descriptive-name
# or
git checkout -b fix/short-descriptive-name
```

3. **Work and commit** with `feat:` or `fix:` prefixed messages:
```bash
git commit -m "feat: add opening accuracy skill"
git commit -m "fix: guard empty games list in watcher"
```

4. **Open PR:**
```bash
gh pr create --title "..." --body "..."
```

5. **Squash-merge and delete remote branch:**
```bash
gh pr merge --squash --delete-branch
```

6. **Return to main and sync:**
```bash
git checkout main && git pull
```

7. **Delete local branch:**
```bash
git branch -D feat/your-branch-name
```
   Use `-D` (capital), not `-d`. After a squash merge, the squashed commit on `main` has a different SHA than your branch's commits, so `git branch -d` will refuse with "not fully merged" even though the PR is merged. `-D` force-deletes, which is safe here because the PR merge is the source of truth.

   Optionally, prune stale remote-tracking refs:
```bash
git fetch --prune
```

### Tagging

Tag `main` at meaningful milestones (not every PR). Use semantic versioning:
- `feat/` work → bump **minor** (v0.6.0 → v0.7.0)
- `fix/` work only → bump **patch** (v0.6.0 → v0.6.1)

```bash
git tag v0.7.0
git push origin v0.7.0
```

Check the latest tag anytime with:
```bash
git describe --tags --abbrev=0
```

## CI/CD (GitHub Actions)
- Pipeline: `.github/workflows/ci.yml` — runs on every push to `main` and `v*` tags
- **4 parallel jobs:**
  - `test` — pytest (fast, excludes `test_domain_security.py`), bandit (SAST), pip-audit (CVE scan)
  - `frontend` — `npm ci && npm run build`
  - `docker` — `docker buildx build` for `linux/amd64` (no push, cache check)
  - `publish` — builds `linux/amd64` + `linux/arm64` and pushes to `ghcr.io/cybersecify/openeasd`
- **Publish triggers:** every push to `main` (`:latest` tag) and `v*` tags (`:vX.Y` tag)
- Runner: `ubuntu-24.04`, Python 3.12, `uv sync --group dev` for deps, `libcairo2-dev gcc` system deps required
- `pip-audit --ignore-vuln PYSEC-2025-183` — disputed PyJWT weak-key-length CVE, no fix available

## Commands
- Always use `uv run python` instead of `python` or `python3`
- Always use `uv run manage.py` for Django management commands (e.g. `uv run manage.py check`)
- Always use `uv run pytest` for running tests
- The slow `tests/unit/test_domain_security.py` (41 tests) makes real DNS/RDAP calls — exclude it for fast CI runs:
  `uv run pytest tests/ --ignore=tests/unit/test_domain_security.py`

## Stack

### Backend
- Django 5+ with plain Django views (no DRF, no Celery, no Redis)
- **Django Ninja** REST API under `/api/` — Schema-based, auto-docs at `/api/docs`
- **JWT Bearer auth** — access + refresh tokens via `djangorestframework-simplejwt` (ninja-jwt wrapper); token blacklist handled by simplejwt's built-in `OutstandingToken`/`BlacklistedToken` models
- **Django-Q2** — background task queue for scan execution AND all scheduling (ORM broker, tasks stored in Django DB). `setup_core_schedules()` in `SchedulerConfig.ready()` registers daily scans, stuck-scan watchdog, JWT token purge, and per-domain monitoring jobs as `django_q.models.Schedule` entries. APScheduler has been fully removed.
- **WhiteNoise** — serves collected static files (frontend bundle) when `DEBUG=False` (Docker/prod); uses `CompressedManifestStaticFilesStorage` for gzip + content-hash fingerprinting
- SQLite database (dev), configurable via `DB_NAME` env var

### Frontend (React SPA — new primary UI)
- **React 19 + Vite 8** — `frontend/` directory, builds to `frontend/dist/`
- **shadcn/ui** — component library on top of Tailwind CSS 3 + Radix UI; CSS variables in `src/index.css`; components in `src/components/ui/`
- Vanilla popstate-based router in `App.jsx` (no react-router)
- JWT `apiFetch` in `src/api/client.js` — sends `Authorization: Bearer <token>` header; 401 clears tokens and redirects to `/login`
- `auth.js` — isolated localStorage helpers (`getToken`, `setTokens`, `clear`, `isLoggedIn`)
- `useFetch` / `usePolling` hooks for data fetching and live scan status (3s poll)
- **Shared components:** `Badge` (cva severity/status variants), `Spinner`, `Pagination`, `ConfirmButton` (AlertDialog), `Notification` (re-exports sonner `toast`)
- **shadcn UI primitives** (`src/components/ui/`): `Button`, `Card`, `Table`, `Badge`, `AlertDialog`, `Pagination`, `Sonner`
- **Toast notifications:** `import { toast } from '../components/Notification.jsx'` → `toast.success()` / `toast.error()`; `<Toaster>` mounted in `main.jsx`
- Dark theme throughout: bg `#0d1117`, card `#161b22`, border `#30363d`, accent `#30c074`; mapped to shadcn CSS vars (`--background`, `--card`, `--border`, `--primary`)
- **Dev:** Vite proxy forwards `/api/` → Django on port **8001** (no CORS config needed)
- **Prod:** `npm run build` → `frontend/dist/` → served by Django via WhiteNoise
- **`/change-password` route** — forced redirect after login if `must_change_password=true`; clears flag on success

### Frontend dev setup
```bash
# Quickest: starts Django (:8001) + Vite dev server + qcluster worker together
make dev

# Or manually in three terminals:
# Terminal 1 — Django
uv run manage.py runserver 8001

# Terminal 2 — Vite dev server (proxies /api/ to Django at :8001)
cd frontend && npm install && npm run dev
# App runs at http://localhost:5173

# Terminal 3 — Background worker (required for scans to execute)
uv run manage.py qcluster
```

### Frontend rules
- New interactive features → React pages in `frontend/src/pages/`
- New API data → add endpoint to the relevant `apps/core/<module>/api.py` router + wire in `apps/core/api/ninja.py`
- Shared UI primitives → `frontend/src/components/`
- Don't add CORS headers — always use same-origin (Vite proxy in dev, Django serves in prod)
- Legacy HTMX/Alpine/Django-template stack is **retired**. All UI is the React SPA.
- SPA catch-all in `openeasd/urls.py` serves `frontend/dist/index.html` for all non-API paths.
- Run `cd frontend && npm run build` to update the production bundle before deployment.

## Deployment

### Docker (production)
```bash
docker run -d \
  -p 8000:8000 \
  -v openeasd-data:/app/data \
  -v openeasd-logs:/app/logs \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e ALLOWED_HOSTS="<IP_OR_DOMAIN>,localhost" \
  --cap-add NET_RAW \
  --restart unless-stopped \
  --name openeasd \
  ghcr.io/cybersecify/openeasd:latest
```
- `--cap-add NET_RAW` — required for nmap raw socket scanning
- `--restart unless-stopped` — survives server reboots
- Volumes: `openeasd-data` (SQLite DB) and `openeasd-logs` persist across container replacements
- Static files served by WhiteNoise (no nginx needed)

### Kubernetes
Manifests in `k8s/`. Deploy with `kubectl apply -k k8s/`.

**Pod layout — single Deployment, single Pod, two containers:**
```
initContainer: init    → migrate + collectstatic + admin user setup (docker-entrypoint.sh)
container: web         → gunicorn openeasd.wsgi:application --bind 0.0.0.0:8000 --workers 2
container: worker      → python manage.py qcluster  (NET_RAW capability for nmap/naabu)
```

**Files:**
```
k8s/
  configmap.yaml        — non-secret env vars; ALLOWED_HOSTS/CSRF are PLACEHOLDERS only
  secret.yaml           — template for SECRET_KEY + real ALLOWED_HOSTS/CSRF (apply out-of-band)
  pvc.yaml              — openeasd-data (10Gi) + openeasd-logs (2Gi), RWO
  deployment.yaml       — single pod with init + web + worker containers
  service.yaml          — ClusterIP, port 80 → 8000
  ingress.yaml          — nginx Ingress; TLS annotations ready to uncomment
  kustomization.yaml    — kubectl apply -k k8s/ (does NOT include secret.yaml)
```

**Key constraints:**
- `replicas: 1` required — SQLite RWO PVC allows single-node access only
- Only `worker` container gets `NET_RAW`; `web` does not need it
- `GET /health/` — unauthenticated endpoint used by K8s readiness/liveness probes
- **Real `ALLOWED_HOSTS`/`CSRF_TRUSTED_ORIGINS` live in `openeasd-secret`, never in
  the committed configmap.** `configmap.yaml` carries only placeholders; the real
  hostname is set in the secret, which is applied out-of-band and is intentionally
  omitted from the kustomize base. Because the deployment's `envFrom` lists
  `secretRef` after `configMapRef` (last source wins), the secret's values override
  the configmap placeholders at runtime. This is deliberate: it keeps the real host
  out of the public repo AND makes `kubectl apply -k k8s/` safe — a re-apply can
  never clobber `ALLOWED_HOSTS` back to the placeholder and 400 the live host.
  Set them when creating the secret (see `k8s/secret.yaml` and `kustomization.yaml`).

**Update running deployment:**
```bash
kubectl rollout restart deployment/openeasd -n default
```

### docker-entrypoint.sh
Runs on every container start (init container in K8s, or `CMD` override in Docker):
1. `manage.py migrate --run-syncdb`
2. `manage.py collectstatic --noinput --clear`
3. Creates `admin/admin` with `must_change_password=True` if no users exist; re-flags if default password still in use
4. `exec "$@"` — hands off to the actual process

### First login
`docker-entrypoint.sh` creates `admin/admin` with `must_change_password=True` on first run. The React app redirects to `/change-password` before allowing access. On every startup, if the default password is still in use, the flag is re-set.

### microk8s deployment (host IP changed)
If the host IP changes, microk8s certs and kubeconfigs reference the old IP and the cluster goes "not running":
1. Update IP-SAN in `/var/snap/microk8s/current/certs/csr.conf.template` (the `IP.3` line), then `sudo microk8s refresh-certs --cert server.crt`.
2. `refresh-certs` does **not** rewrite the client kubeconfigs — sed-replace the old `server: https://<old-ip>:16443` in `/var/snap/microk8s/current/credentials/{client,kubelet,controller,scheduler,proxy}.config`.
3. `refresh-certs` also does **not** cover `kubelet.crt` (the kubelet's serving cert) — regenerate it manually with openssl, signed by `ca.crt`/`ca.key`, with Subject `CN=system:node:<hostname>, O=system:nodes` and SANs `DNS:<hostname>, IP:<new-host-ip>, IP:127.0.0.1`. Without this, `kubectl logs`/`exec` fail with "certificate is valid for <old-ip>".
4. Restart with `sudo microk8s stop && sudo microk8s start` (or just `systemctl restart snap.microk8s.daemon-kubelite` if only kubelet.crt changed).
5. Backups from `microk8s refresh-certs` land in `/var/snap/microk8s/<rev>/certs-backup/`; manual kubelet regen leaves `kubelet.crt.bak.<epoch>` next to the new cert.

### microk8s + host Caddy
Don't enable the `ingress` addon if the host already runs Caddy on :80/:443 — the nginx-ingress DaemonSet uses `hostPort` 80/443, and CNI portmap iptables intercept all traffic in PREROUTING before it reaches Caddy, silently breaking every Caddy site. Instead: expose the service as `NodePort` (e.g. 30808) and have Caddy `reverse_proxy localhost:<nodeport>`. The probe still needs `httpHeaders: [{name: Host, value: <ALLOWED_HOSTS-entry>}]` because kubelet sends the pod IP as Host by default and Django rejects it with 400.

### Scheduler
- Daily scan runs at `SCAN_DAILY_HOUR:SCAN_DAILY_MINUTE` (uses `TIME_ZONE` in settings, default 02:00)
- Configured via env vars: `SCAN_DAILY_HOUR`, `SCAN_DAILY_MINUTE`
- Schedule history visible in Django admin under "Django Q" → "Scheduled tasks"
- Scheduler code lives in `apps/core/scheduler/scheduler.py`
- `setup_core_schedules()` called from `apps/core/scheduler/apps.py` → `SchedulerConfig.ready()`
- Guard runs only in the qcluster process (checks `qcluster` in `sys.argv`) — never runs in gunicorn workers

## External binary tools

ProjectDiscovery tools installed via `pdtm` at `~/.pdtm/go/bin/`:
- `subfinder`, `dnsx`, `naabu`, `httpx`, `katana`, `nuclei`

OWASP/other tools:
- `amass` — active subdomain enumeration (install separately: `go install -v github.com/owasp-amass/amass/v4/...@master`)

System binary:
- `nmap` (Homebrew at `/opt/homebrew/bin/nmap`)

Tool paths are configurable via `TOOL_SUBFINDER`, `TOOL_DNSX`, `TOOL_NAABU`, `TOOL_HTTPX`, `TOOL_KATANA`, `TOOL_NMAP`, `TOOL_NUCLEI`, `TOOL_AMASS`, `TOOL_ALTERX`, `TOOL_CLOUD_ENUM` env vars.

## Architecture

### Core infrastructure — `apps/core/` (14 sub-apps)

| App | Label | Purpose |
|---|---|---|
| `dashboard/` | `core` | Dashboard page, health check; **UserProfile** model (`must_change_password` flag) |
| `domains/` | `domains` | Domain model, CRUD views |
| `assets/` | `assets` | Network assets: Subdomain, IPAddress, Port |
| `web_assets/` | `web_assets` | Web assets: URL |
| `service_detection/` | `service_detection` | Enriches Port.service + Port.is_web via nmap -sV |
| `findings/` | `findings` | Unified Finding model — all tools write here |
| `scans/` | `scans` | ScanSession, ScanDelta, pipeline orchestrator |
| `workflows/` | `workflow` | Workflow CRUD, dynamic runner, tool registry |
| `scheduler/` | `scheduler` | Django-Q2 schedule setup, daily/weekly scans, per-domain monitoring, stuck scan watchdog |
| `notifications/` | `alerts` | Slack/Teams alerts, NotificationConfig model, alert history |
| `insights/` | `insights` | ScanSummary, FindingTypeSummary, charts |
| `reports/` | `reports` | CSV + PDF export |
| `api/` | — | Django Ninja API — routers, JWT auth, error handlers |

### REST API module — `apps/core/api/`

```
apps/core/api/
    __init__.py
    ninja.py          — NinjaAPI instance, ninja-jwt auth routes (/token/pair|refresh|verify|blacklist),
                        /user/ endpoint, error handlers, router registration

Per-module routers (each file exports a `router = Router(auth=JWTAuth())`):
    apps/core/dashboard/api.py   — /api/dashboard/
    apps/core/domains/api.py     — /api/domains/ CRUD
    apps/core/scans/api.py       — /api/scans/ + findings
    apps/core/workflows/api.py   — /api/workflows/ CRUD + /tools/
    apps/core/insights/api.py    — /api/insights/
    (scheduled router in scans/api.py) — /api/scheduled/
```

**Response format:** Flat JSON — no envelope wrapper.
```json
{"id": 1, "domain": "example.com", ...}           // success
{"error": {"code": "NOT_FOUND", "message": "..."}} // error
```

**Auth:** JWT Bearer tokens via ninja-jwt (simplejwt). React stores tokens in `localStorage` via `auth.js`.
- Access token: short-lived, sent as `Authorization: Bearer <token>`
- Refresh token: long-lived, sent in POST body to `/api/token/refresh`
- Logout: blacklists refresh token via `/api/token/blacklist` (simplejwt OutstandingToken/BlacklistedToken)

**Adding a new API endpoint:**
1. Add endpoint function to the relevant `apps/core/<module>/api.py` router
2. Register the router in `apps/core/api/ninja.py` if it's a new module
3. Consume in `frontend/src/api/client.js` or a page component

### Tool auto-registration

Tools self-register via `AppConfig.tool_meta`. **No core files need editing when adding a new tool** (except `settings.INSTALLED_APPS`).

```python
# Example: apps/my_tool/apps.py
class MyToolConfig(AppConfig):
    name = "apps.my_tool"
    label = "my_tool"
    verbose_name = "My Tool"
    tool_meta = {
        "label": "My Tool",
        "runner": "apps.my_tool.scanner.run_my_tool",
        "phase": 7,
        "phase_group": "Network Exposure",
        "requires": ["naabu"],
        "produces_findings": True,
    }
```

The registry (`apps/core/workflows/registry.py`) auto-discovers all `tool_meta` at startup and provides:
- `get_tool_choices()` — for forms and UI
- `get_tool_runners()` — for workflow execution
- `get_tool_phases()` — for ordering
- `get_tool_phase_groups()` — maps tool → phase_group label
- `get_tool_requires()` — for dependency validation
- `get_source_choices()` — for finding source filtering

### Tool apps (19 registered tools)

| App | Phase | Phase Group | produces_findings | Description |
|---|---|---|---|---|
| `apps/domain_security/` | 1 | Domain Intelligence | Yes | DNS, email, RDAP checks |
| `apps/subfinder/` | 2 | Surface Enumeration | No | Passive subdomain enumeration |
| `apps/amass/` | 2 | Surface Enumeration | No | Active subdomain enumeration |
| `apps/alterx/` | 2 | Surface Enumeration | No | Subdomain permutation via alterx (generates candidates from discovered subdomains) |
| `apps/dnsx/` | 3 | Surface Enumeration | No | DNS resolution, public IP filtering |
| `apps/takeover_check/` | 4 | Surface Enumeration | Yes | Subdomain takeover detection via subzy (dangling DNS → unclaimed cloud) |
| `apps/cloud_assets/` | 4 | Surface Enumeration | Yes | Public cloud bucket enumeration via cloud_enum (AWS S3 / Azure Blob / GCP Storage) |
| `apps/naabu/` | 5 | Port Discovery | No | Port scanning (top 100 TCP) |
| `apps/core/service_detection/` | 6 | Port Discovery | No | nmap -sV enriches Port.service + is_web |
| `apps/nmap/` | 7 | Network Exposure | Yes | NSE vulners CVE scan (non-web ports); backport-aware CVE matching (`backports.json` registry) |
| `apps/tls_checker/` | 7 | Network Exposure | Yes | TLS/cert analysis + cipher suite enumeration via `nmap --script ssl-enum-ciphers` (all ports) |
| `apps/ssh_checker/` | 7 | Network Exposure | Yes | SSH config analysis |
| `apps/nuclei_network/` | 7 | Network Exposure | Yes | Network protocol vuln scan (319 templates, non-web) |
| `apps/httpx/` | 8 | Web Exposure | No | Web probing, URL discovery |
| `apps/historical_urls/` | 9 | Web Exposure | No | Historical URL discovery via gau + waybackurls (Wayback Machine, OTX, Common Crawl) |
| `apps/katana/` | 10 | Web Exposure | No | Web crawling, endpoint discovery |
| `apps/nuclei/` | 11 | Web Exposure | Yes | Web vuln scan (community templates) |
| `apps/web_checker/` | 11 | Web Exposure | Yes | Security headers, cookies, CORS |
| `apps/cve_intel/` | 12 | Prioritization | No | Enriches CVE findings in place with EPSS scores + CISA KEV flags (no new findings) |

### Tool app structure
```
apps/<tool>/
    apps.py         — AppConfig with tool_meta (self-registration)
    models.py       — empty (writes to apps/core/assets/ and apps/core/findings/)
    scanner.py      — thin orchestrator: collect → analyze → save
    collector.py    — runs binary or probes, returns raw data (no DB)
    analyzer.py     — parses raw data, builds shared Asset/Finding objects
```

## Scan pipeline

All scans run through the **dynamic workflow system**. The default "Full Scan"
workflow executes all 19 tools in phase order. Custom workflows can include
any subset of tools.

```
Phase 1  domain_security    → Finding (DNS/email/RDAP)
Phase 2  subfinder          → Subdomain (passive enumeration)
Phase 2  amass              → Subdomain (active enumeration)
Phase 2  alterx             → Subdomain (permutation candidates from existing subdomains)
Phase 3  dnsx               → IPAddress (public-only filter)
Phase 4  takeover_check     → Finding (subzy — dangling DNS → unclaimed cloud)
Phase 4  cloud_assets       → Finding (open S3/Azure/GCP buckets — cloud_enum)
Phase 5  naabu              → Port (top 100 TCP scan)
Phase 6  service_detection  → enriches Port.service + Port.is_web
Phase 7  nmap               → Finding (CVEs on non-web ports, is_web=False)  ┐
Phase 7  tls_checker        → Finding (cipher/cert/protocol on all ports)    │ parallel
Phase 7  ssh_checker        → Finding (SSH config on service="ssh" ports)    │
Phase 7  nuclei_network     → Finding (network protocol vulns, non-web ports)┘
Phase 8  httpx              → URL (web probing, CDN-aware via SNI)
Phase 9  historical_urls    → URL (gau + waybackurls — archived endpoints)
Phase 10 katana             → URL (web crawling, endpoint discovery)
Phase 11 nuclei             → Finding (web vulns via templates on URLs)
Phase 11 web_checker        → Finding (headers, cookies, CORS on URLs)
```

### Scan flow
```
create_scan_session(domain)          # auto-assigns default workflow
  → run_scan_task(session_id)        # Huey async task
    → run_scan(session_id)           # sets status="running"
      → _run_via_workflow(session)   # creates WorkflowRun, calls run_workflow()
        → run_workflow(run_id)       # loops enabled tools, records StepResults
      → _finalize_session(session)   # count findings, deltas, insights, alerts
```

### Key design rules
1. **Tools never import from each other.** Shared data flows through `apps/core/assets/`, `apps/core/web_assets/`, and `apps/core/findings/`.
2. **Tools self-register.** Add `tool_meta` to AppConfig + add to `INSTALLED_APPS`. No other core files to touch.
3. **Port.is_web** classifies ports. Set by `service_detection` (Phase 6) based on nmap -sV service name. Used by nmap to skip web ports (`is_web=False` only). tls_checker probes all ports — including HTTPS (port 443).
4. **dnsx filters to public IPs only.** Private/loopback/link-local/AWS metadata IPs dropped.
5. **httpx feeds subdomain:port pairs, not IP:port pairs.** Cloudflare/CDN-fronted services need SNI matching.
6. **nmap only scans non-web ports** (`Port.objects.filter(is_web=False)`).
7. **Asset deletion cascades:** Subdomain → IPAddress → Port → URL. Deleting a Domain wipes all session data.
8. **Delta detection** compares ALL findings between current and previous scan for the same domain.

## Unified Finding model

`apps/core/findings/Finding` — all tools write to it:

```python
class Finding(models.Model):
    session     = FK(ScanSession)
    source      = CharField()      # auto-registered from tool_meta
    check_type  = CharField()      # tool-specific: "dns", "cve", "weak_ssh_kex", etc.
    severity    = "critical" | "high" | "medium" | "low" | "info"
    title       = CharField()
    description = TextField()
    remediation = TextField()
    target      = CharField()      # hostname or IP:port
    port        = FK(Port, null=True)
    url         = FK(web_assets.URL, null=True)
    extra       = JSONField()      # tool-specific: cve, cvss_score, cipher_name, etc.
```

**SQLite quirk:** Don't use `Max("extra__cvss_score")` or other aggregations on JSON-extracted fields — Django/SQLite fails. Group in Python instead.

## URL layout

### REST API (`/api/`)
```
POST /api/token/pair                      — JWT login → {access, refresh}
POST /api/token/blacklist                 — blacklist refresh token (logout)
POST /api/token/refresh                   — exchange refresh → new access token
POST /api/token/verify                    — verify token validity
GET  /api/user/                           — current user info + must_change_password flag
POST /api/user/change-password/           — change password; clears must_change_password flag
GET  /api/dashboard/                      — KPIs, domain status, urgent findings
GET  /api/domains/                        — list domains (enriched)
POST /api/domains/                        — add domain
POST /api/domains/<pk>/toggle/            — activate/deactivate
POST /api/domains/<pk>/delete/            — delete domain + all scan data
GET  /api/scans/                          — paginated scan list (?domain=&status=&page=)
POST /api/scans/start/                    — start/schedule scan
GET  /api/scans/<uuid>/                   — full scan detail (assets + findings)
GET  /api/scans/<uuid>/status/            — lightweight status (React polls every 3s)
POST /api/scans/<uuid>/stop/              — cancel running scan
POST /api/scans/<uuid>/delete/            — delete scan session
GET  /api/scans/findings/                 — paginated findings (?severity=&domain=&status=&source=)
POST /api/scans/findings/<id>/status/     — update finding lifecycle status
GET  /api/scheduled/                      — scheduled jobs list
POST /api/scheduled/<job_id>/cancel/      — cancel scheduled job
GET  /api/workflows/                      — list workflows
POST /api/workflows/create/               — create workflow
GET  /api/workflows/tools/                — all registered tool choices (for create form)
GET  /api/workflows/<pk>/                 — workflow detail + tool_steps + recent runs
POST /api/workflows/<pk>/update/          — update workflow name/tools
POST /api/workflows/<pk>/delete/          — delete workflow
POST /api/workflows/<pk>/steps/<tool>/toggle/ — toggle single tool step
GET  /api/insights/                       — trends, top hosts, asset growth, KPIs
```

### Other routes
- `/reports/<uuid>/csv/` → CSV export (Django view, `_report_auth_required` — accepts session auth or `?token=<access_token>`)
- `/reports/<uuid>/pdf/` → PDF export (Django view, `_report_auth_required` — accepts session auth or `?token=<access_token>`)
- `/admin/` → Django admin
- `/api/docs` → Django Ninja auto-generated OpenAPI docs
- `/*` → React SPA catch-all (`frontend/dist/index.html`)

## Tests

| File | Tests | Notes |
|---|---|---|
| `tests/unit/test_alerts.py` | 7 | Slack/Teams dispatcher |
| `tests/unit/test_assets.py` | 13 | Asset model constraints, FK chains, cascade delete |
| `tests/unit/test_core.py` | 10 | Dashboard view |
| `tests/unit/test_dnsx.py` | 20 | Public IP filter, analyzer, scanner |
| `tests/unit/test_domain_security.py` | 41 | DNS/email/RDAP — **slow, real network** |
| `tests/unit/test_domains.py` | 15 | Domain CRUD |
| `tests/unit/test_httpx.py` | 11 | JSON parser, Port lookup, Subdomain link |
| `tests/unit/test_katana.py` | 18 | JSONL parser, Port/Subdomain FK links, scanner orchestrator |
| `tests/unit/test_historical_urls.py` | 37 | collector (_run_tool: missing binary, timeout, happy path), analyzer (noise filter, FK links, dedup), scanner (root domain, subdomains, persist, dedup) |
| `tests/unit/test_insights.py` | 11 | Insights builder + view |
| `tests/unit/test_naabu.py` | 9 | JSON parser, FK to IPAddress |
| `tests/unit/test_nmap.py` | 23 | Severity mapping, vulners XML parser, web/non-web exclusion, backport matching |
| `tests/unit/test_reports.py` | 20 | CSV export content/structure, PDF export (mocked pisa), min_severity filter |
| `tests/unit/test_scans.py` | 55 | ScanSession, scheduling, scan_start views |
| `tests/unit/test_scheduler.py` | 15 | reap_stuck_scans, purge_expired_tokens, daily_scan |
| `tests/unit/test_subfinder.py` | 11 | JSON parser, dedup, hostname normalization |
| `tests/unit/test_alterx.py` | 17 | collector (binary missing, timeout, happy path, stdin), analyzer (dedup, validation, session dedup, lowercase), scanner (no subdomains, persist, return) |
| `tests/unit/test_tls_checker.py` | 87 | Cert parsing, ciphers, protocols, HSTS, collector, scanner, cipher enumeration |
| `tests/unit/test_ssh_checker.py` | 33 | SSH probe, host key, kex/cipher/MAC, auth, collector |
| `tests/unit/test_nuclei.py` | 25 | CVE parsing, severity, dedup, URL linking, collector |
| `tests/unit/test_web_checker.py` | 40 | Headers, cookies, CORS, disclosure, collector |
| `tests/unit/test_service_detection.py` | 16 | XML parsing, Port enrichment, is_web |
| `tests/unit/test_workflow_runner.py` | 31 | run_workflow, service_detection injection, step failure, cancellation, phase parallelism |
| `tests/unit/test_takeover_check.py` | 35 | collector (binary missing, bad JSON, happy path), analyzer (vulnerable/non-vulnerable, FK link, dedup, extra field), scanner (no subdomains, persist + return) |
| `tests/unit/test_cloud_assets.py` | 20 | cloud_assets collector, analyzer, keyword derivation, scanner |
| `tests/integration/test_scan_flow.py` | 13 | Full pipeline (mocked) + delete cascade |
| `tests/test_api_endpoints.py` | 71 | Smoke tests for all 35 API endpoints (auth + payload shape) |

**Total: ~963 tests** (~922 fast + 41 slow domain_security)
