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
- Runner: `ubuntu-24.04`, Python 3.12, `uv sync --group dev` for deps, `libcairo2-dev gcc libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0` system deps required (WeasyPrint PDF rendering)
- `pip-audit --ignore-vuln PYSEC-2025-183` — disputed PyJWT weak-key-length CVE, no fix available
- **Build provenance:** the `publish` job computes `OPENEASD_VERSION` (git tag for `v*`, else `pyproject.toml` version), `OPENEASD_GIT_SHA` (`github.sha`), and `OPENEASD_BUILD_DATE` (ISO UTC) and passes them as `build-args` to buildx. The Dockerfile bakes them into `ENV` (placed late so they never bust the cache of the heavy layers). Settings read them via `config()` with `dev`/`unknown` defaults for local runs. Surfaced at `GET /health/` + `GET /api/version/`, and shown as a muted footer on the login + change-password pages AND in the authenticated app sidebar (`frontend/src/components/BuildInfo.jsx`). The sidebar footer also does an "update available" check via `GET /api/version/latest/` (authenticated; compares the running build to the latest GitHub release, cached 6h, fail-graceful — logic in `apps/core/api/update_check.py`). The app never self-updates; it only surfaces a heads-up + release link.

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
- **react-router-dom** — `createBrowserRouter` route tree in `src/router.jsx`; auth-gated routes via a `ProtectedRoute` (`Outlet` + `<Navigate to="/login">`) that checks `auth.isLoggedIn()`. There is no `App.jsx`; `main.jsx` renders `<RouterProvider>`.
- `src/api/client.js` — thin `apiGet(path)` / `apiPost(path, body)` wrappers over `axiosInstance.js`. The axios instance's request interceptor adds `Authorization: Bearer <token>`; the response interceptor, on 401, silently refreshes via `/api/token/refresh` (single shared `_refreshPromise` dedupes concurrent refreshes) and only clears tokens + redirects to `/login` if refresh fails.
- `auth.js` — isolated localStorage helpers (`getToken`, `getRefresh`, `setTokens`, `clear`, `isLoggedIn`)
- **@tanstack/react-query** — `useQuery({ queryKey: [path, ...deps], queryFn: () => apiGet(path) })` for all data fetching; `queryClient` in `src/lib/queryClient.js` (`staleTime: 0`, `retry: false`), `<QueryClientProvider>` in `main.jsx`. Live scan status polls via `refetchInterval: shouldPoll ? 3000 : false` (3s). No custom `useFetch`/`usePolling` hooks.
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
- New interactive features → React pages in `frontend/src/pages/`, wired into the route tree in `src/router.jsx`
- Fetch data with react-query `useQuery` + `apiGet`/`apiPost` (keyed by the API path); don't reintroduce ad-hoc `fetch`/`useFetch`. Navigate with react-router-dom's `useNavigate`, not a hand-rolled router.
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
- **RAM: 2 GB min / 4 GB recommended.** nuclei + amass are memory-hungry and the
  kernel will OOM-kill them on an under-provisioned host (silent partial scans).
  `OPENEASD_PROFILE` (default `auto`, from RAM) tunes this: `low` (<2GB or
  `OPENEASD_LOW_MEMORY=true`) runs tools sequentially + throttles nuclei + skips
  amass brute so ~1GB completes without OOM; `balanced` (2-8GB) is the old
  default; `high` (≥8GB) raises LOCAL concurrency. Per-target request rate stays
  capped across all profiles (politeness — a big box is no licence to hammer the
  target; higher rates just trip WAFs, which the coverage report flags). Add
  swap on 1GB hosts. Resolver + tuning in settings.py (`_resolve_profile`,
  `_PROFILE_TUNING`). nuclei is also severity-scoped per profile (`NUCLEI_SEVERITY`;
  low=critical/high/medium, else +low; `info` dropped everywhere) — the fix for
  its freeze/timeout since it compiles all ~13.5k templates into RAM. See
  `docs/SCAN_OPERATIONAL_LEARNINGS.md`.
- Volumes: `openeasd-data` (SQLite DB) and `openeasd-logs` persist across container replacements
- Static files served by WhiteNoise (no nginx needed)
- **Serve it over HTTPS.** Do NOT expose the app on bare HTTP — login sends
  credentials and JWTs in cleartext. Put a TLS-terminating reverse proxy in
  front (Caddy/nginx + Let's Encrypt on a real domain, or Cloudflare) — a bare
  IP like `http://<ip>/` cannot get a normal cert and must not be used with real
  credentials. The app already sends `SECURE_PROXY_SSL_HEADER`; once TLS is in
  front, enable enforcement via env: `SECURE_SSL_REDIRECT=true` and
  `SECURE_HSTS_SECONDS=31536000`. `SESSION_COOKIE_SECURE`/`CSRF_COOKIE_SECURE`
  are already on by default when `DEBUG=False`.

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
- `GET /health/` — unauthenticated endpoint used by K8s readiness/liveness probes; JSON body is `{status, version, git_sha (short 8), build_date}` (build provenance)
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
- **Auto-scan consent gate:** `daily_scan` and per-domain monitoring only scan domains with a `DomainAuthorization` record (`is_active=True, authorization__isnull=False`); `run_monitoring_scan` re-checks at run time. The scheduler cannot bypass the authorization gate the manual API/UI already enforce. (Scheduled scans always run the default active Full Scan workflow, so the gate always applies to them — the passive-scan exemption below is manual/`now`-only.)
- **`SCHEDULED_SCANS_ENABLED`** (env, default `True`) is the master switch for unattended scanning. When `False`, `setup_core_schedules()` registers only the hygiene jobs (watchdog + token purge) and removes any existing `daily_scan`/`monitor_*` schedules on startup — this is how a deployment is made durably manual-only (set in `k8s/configmap.yaml`). Manual/API scans are unaffected.
- Schedule history visible in Django admin under "Django Q" → "Scheduled tasks"
- Scheduler code lives in `apps/core/scheduler/scheduler.py`
- `setup_core_schedules()` called from `apps/core/scheduler/apps.py` → `SchedulerConfig.ready()`
- Guard runs only in the qcluster process (checks `qcluster` in `sys.argv`) — never runs in gunicorn workers

## External binary tools

ProjectDiscovery tools installed via `pdtm` at `~/.pdtm/go/bin/`:
- `subfinder`, `dnsx`, `naabu`, `httpx`, `katana`, `nuclei`

OWASP/other tools:
- `amass` — active subdomain enumeration (install separately: `go install -v github.com/owasp-amass/amass/v4/...@master`)
- `gitleaks` — hardcoded-secret detection over fetched JS assets (MIT, static Go binary from `github.com/gitleaks/gitleaks` releases; baked into the Docker image)

System binary:
- `nmap` (Homebrew at `/opt/homebrew/bin/nmap`)

Tool paths are configurable via `TOOL_SUBFINDER`, `TOOL_DNSX`, `TOOL_NAABU`, `TOOL_HTTPX`, `TOOL_KATANA`, `TOOL_NMAP`, `TOOL_NUCLEI`, `TOOL_AMASS`, `TOOL_ALTERX`, `TOOL_CLOUD_ENUM`, `TOOL_GITLEAKS` env vars.

**Honest scanner identity:** httpx/katana/nuclei send `OPENEASD_USER_AGENT`
(default `OpenEASD/1.0 (+https://cybersecify.com/openeasd)`) so a target can
allowlist us deliberately. The httpx analyzer classifies each probe's
`URL.reachability` (`reached`/`blocked`/`challenged`/`rate_limited`, via
`apps/httpx/waf.py`); `_finalize_session` aggregates it into `ScanSession`
coverage fields (`waf_vendor`, `endpoints_probed`, `endpoints_blocked`), surfaced
as a "Scan Coverage" block in the PDF report. See
`docs/specs/2026-08-16-waf-coverage-honest-scope.md` (Phase 1: C1–C3; the
request-counting proxy C4 is deferred).

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
    apps/core/notifications/api.py — /api/notifications/ config + test + alerts
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

Tools self-register via `AppConfig.tool_meta`. No core *code* needs editing to
register a tool — but registration alone does **not** put it in a scan.

**Definition of done for adding (or removing) a tool** — all of these, or the
registry, the scan, the report, and the public docs drift out of sync (this is
how asn_discovery/js_secrets shipped registered-but-not-scanned, reading 21 in
the registry and 19 in every actual scan):

1. Add the app to `settings.INSTALLED_APPS`.
2. **Add it to the default Full Scan workflow** via a data migration (unless it
   is deliberately default-off — then document why). Enforced by
   `tests/unit/test_default_workflow.py::test_full_scan_covers_every_registered_tool`,
   which fails CI if a registered non-core tool is missing from Full Scan.
3. Set the `"active"` flag correctly (passive = no target contact → no auth).
4. Update `README.md` — the tool count, the tool list, and the pipeline diagram.
5. Update `CHANGELOG.md` (What + Why) and the tool tables in this file.
6. **Flag the website session** — cybersecify.com's tool count, feature cards,
   and the sample report must match. Keeping GitHub + website in sync on any
   tool/feature change is a standing requirement, not an afterthought.

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

### Tool apps (22 registered tools)

| App | Phase | Phase Group | produces_findings | Description |
|---|---|---|---|---|
| `apps/domain_security/` | 1 | Domain Intelligence | Yes | DNS, email, RDAP checks |
| `apps/hudson_rock/` | 1 | Domain Intelligence | Yes | Infostealer-log exposure via Hudson Rock's keyless Cavalier API (aggregate counts only, no plaintext); passive, fail-graceful |
| `apps/subfinder/` | 2 | Surface Enumeration | No | Passive subdomain enumeration |
| `apps/amass/` | 2 | Surface Enumeration | No | Active subdomain enumeration |
| `apps/asn_discovery/` | 2 | Surface Enumeration | Yes | Owned ASN / CIDR discovery via `amass intel` (passive registry/BGP recon); reports ranges only, no auto-scan expansion |
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
| `apps/httpx/` | 8 | Web Exposure | No | Web probing, URL discovery, technology fingerprinting (`-tech-detect` → `URL.technologies`) |
| `apps/historical_urls/` | 9 | Web Exposure | No | Historical URL discovery via gau + waybackurls (Wayback Machine, OTX, Common Crawl) |
| `apps/katana/` | 10 | Web Exposure | No | Web crawling, endpoint discovery |
| `apps/nuclei/` | 11 | Web Exposure | Yes | Web vuln scan (community templates) |
| `apps/web_checker/` | 11 | Web Exposure | Yes | Security headers, cookies, CORS |
| `apps/js_secrets/` | 11 | Web Exposure | Yes | Hardcoded-secret detection — fetches discovered `.js` assets and runs gitleaks over them; secret is redacted before storage |
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
workflow executes the full tool set in phase order. Custom workflows can include
any subset of tools. (A newly registered tool is available to any workflow, but
only joins the default Full Scan when a data migration appends it — see
`workflows/migrations/0021_*`; `asn_discovery` and `js_secrets` are registered
but not yet in the default set.)

```
Phase 1  domain_security    → Finding (DNS/email/RDAP)
Phase 1  hudson_rock         → Finding (infostealer exposure via Hudson Rock — passive)
Phase 2  subfinder          → Subdomain (passive enumeration)
Phase 2  amass              → Subdomain (active enumeration)
Phase 2  asn_discovery      → Finding (owned ASN/CIDR ranges via amass intel — informational)
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
Phase 11 js_secrets         → Finding (gitleaks over fetched .js assets — secret redacted)
```

### Passive vs active scan modes (the authorization boundary)

Every tool carries an `"active": True/False` flag in its `tool_meta`, exposed by
the registry via `get_tool_active()` and `is_passive_tool_set(tools)`.

- **Passive** (`active=False`): uses ONLY public / third-party data — CT logs and
  other subdomain feeds, DNS resolution via public resolvers, WHOIS/RDAP, web
  archives, cloud-provider bucket APIs, CVE/EPSS/KEV feeds. Sends **no packets to
  the target's own systems**. Needs **no `DomainAuthorization`**.
  Passive tools: `subfinder`, `alterx`, `dnsx`, `historical_urls`,
  `cloud_assets`, `cve_intel`, `asn_discovery`, `hudson_rock`.
- **Active** (`active=True`): probes the target directly (port scans, HTTP/TLS/SSH
  connections, crawling, vuln templates, AXFR/SMTP/mta-sts probes). **Requires
  `DomainAuthorization`.**
  Active tools: `domain_security`, `amass`, `takeover_check`, `naabu`,
  `service_detection`, `nmap`, `tls_checker`, `ssh_checker`, `nuclei_network`,
  `httpx`, `katana`, `nuclei`, `web_checker`.

**Default is active.** `tool_meta` omitting `"active"` is treated as active — a
missing flag can never let a scanner probe an unauthorized target.

**`domain_security` is active, not passive**, despite being mostly DNS lookups: it
also performs AXFR zone transfers, SMTP open-relay probes, and mta-sts policy
fetches directly against the target. A tool with ANY code path that touches the
target is active.

**Authorization rule (`apps/core/scans/api.py`):** a `schedule_type="now"` scan
whose resolved workflow contains **only passive tools** bypasses the
`DomainAuthorization` gate. Any active tool, a bare `now` scan (default = active
Full Scan), or any scheduled (`once`/`recurring`) scan keeps the gate. The
`subscan` endpoint applies the same rule: an active-tool subscan requires
authorization for the parent scan's domain.

**"Passive Scan" workflow** (migration `0022_create_passive_scan_workflow.py`):
predefined, non-default, contains only passive tools — a no-auth recon mode.
`tests/unit/test_passive_scan.py` asserts every step is passive, so adding an
active tool there fails CI.

**Runner safety fix:** `service_detection` (active nmap -sV) is auto-injected only
when `naabu` is in the run. A passive/naabu-less workflow therefore never triggers
an active probe.

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
GET  /api/version/                        — build provenance {version, git_sha, git_sha_short, build_date, support_email} (unauthenticated; no-store)
GET  /api/version/latest/                 — update check {current_version, latest_version, update_available, release_url} (authenticated; cached 6h, fail-graceful)
GET  /api/user/                           — current user info + must_change_password flag
POST /api/user/change-password/           — change password; clears must_change_password flag
GET  /api/dashboard/                      — KPIs, domain status, urgent findings
GET  /api/domains/                        — list domains (enriched)
POST /api/domains/                        — add domain
POST /api/domains/<pk>/toggle/            — activate/deactivate
POST /api/domains/<pk>/delete/            — delete domain + all scan data
POST /api/domains/<pk>/monitoring/        — set/clear per-domain monitoring interval
POST /api/domains/<pk>/authorize/         — grant DomainAuthorization (attestation required)
GET  /api/scans/                          — paginated scan list (?domain=&status=&page=)
POST /api/scans/start/                    — start/schedule scan
GET  /api/scans/<uuid>/                   — full scan detail (assets + findings)
GET  /api/scans/<uuid>/status/            — lightweight status (React polls every 3s)
POST /api/scans/<uuid>/stop/              — cancel running scan
POST /api/scans/<uuid>/delete/            — delete scan session
POST /api/scans/<uuid>/subscan/           — re-run a single tool / subset against an existing scan
GET  /api/scans/urls/                     — paginated web-asset URLs (?domain=&page=)
GET  /api/scans/findings/                 — paginated findings (?severity=&domain=&status=&source=)
POST /api/scans/findings/<id>/status/     — update finding lifecycle status
GET  /api/scheduled/                      — scheduled jobs list
POST /api/scheduled/<job_id>/cancel/      — cancel scheduled job
GET  /api/workflows/                      — list workflows
POST /api/workflows/create/               — create workflow
GET  /api/workflows/tools/                — all registered tool choices (for create form)
GET  /api/workflows/<pk>/                 — workflow detail + tool_steps + recent runs
POST /api/workflows/<pk>/update/          — update workflow name/tools
POST /api/workflows/<pk>/rename/          — rename workflow
POST /api/workflows/<pk>/delete/          — delete workflow
POST /api/workflows/<pk>/steps/<tool>/toggle/ — toggle single tool step
GET  /api/insights/                       — trends, top hosts, asset growth, KPIs
GET  /api/notifications/config/           — get Slack/Teams notification config
POST /api/notifications/config/           — update notification config
POST /api/notifications/test/             — send a test alert
GET  /api/notifications/alerts/           — alert history
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
| `tests/unit/test_alterx.py` | 17 | collector (binary missing, timeout, happy path, stdin), analyzer, scanner |
| `tests/unit/test_amass.py` | 21 | Active subdomain enum collector, analyzer, scanner |
| `tests/unit/test_asn_discovery.py` | 22 | ASN/CIDR discovery — org derivation, ASN/CIDR parsing, collector (binary missing, timeout, two-step happy path), analyzer (info Finding per ASN, safe-scope remediation), scanner |
| `tests/unit/test_assets.py` | 12 | Asset model constraints, FK chains, cascade delete |
| `tests/unit/test_cloud_assets.py` | 20 | cloud_assets collector, analyzer, keyword derivation, scanner |
| `tests/unit/test_cve_intel.py` | 24 | EPSS/KEV enrichment, CVE extraction (both finding shapes), feed-failure fallback |
| `tests/unit/test_dnsx.py` | 21 | Public IP filter, analyzer, scanner |
| `tests/unit/test_domain_authorization.py` | 10 | DomainAuthorization model + scan-entry gating |
| `tests/unit/test_domain_security.py` | 52 | DNS/email/RDAP — **slow, real network** |
| `tests/unit/test_domains.py` | 13 | Domain CRUD |
| `tests/unit/test_historical_urls.py` | 37 | collector (missing binary, timeout, happy path), analyzer (noise filter, FK links, dedup), scanner |
| `tests/unit/test_httpx.py` | 16 | JSON parser, Port lookup, Subdomain link, honest UA, tech-detect flag + technology storage/dedup |
| `tests/unit/test_hudson_rock.py` | 17 | collector (both endpoints keyless + honest UA, fail-graceful on timeout/500/429/bad-JSON, 429 retry), analyzer (severity, counts/families/URLs/attribution, no-finding-when-zero, **no plaintext/email persisted**, URL cap), scanner |
| `tests/unit/test_js_secrets.py` | 26 | `.js` URL filter + cap, fetch-error handling, gitleaks JSON parser, analyzer Findings + dedup + secret redaction (full secret never stored), scanner, binary-missing/timeout |
| `tests/unit/test_k8s_manifests.py` | 59 | k8s manifest structure, envFrom order, probes, secret/configmap split |
| `tests/unit/test_katana.py` | 19 | JSONL parser, Port/Subdomain FK links, scanner orchestrator, honest UA |
| `tests/unit/test_management_commands.py` | 11 | `verify_tools` + other management commands |
| `tests/unit/test_monitoring.py` | 17 | sync_domain_monitoring_jobs, per-domain monitoring, authorization gate |
| `tests/unit/test_naabu.py` | 10 | JSON parser, FK to IPAddress |
| `tests/unit/test_nmap.py` | 26 |
| `tests/unit/test_nmap_backports.py` | 16 | Backport-aware CVE demotion engine — Debian/Ubuntu version compare, check_backport, `protocol 2.0` false-positive guard | Severity mapping, vulners XML parser, web/non-web exclusion, backport matching |
| `tests/unit/test_notifications.py` | 25 | NotificationConfig, Slack/Teams alerts, alert-history API |
| `tests/unit/test_nuclei.py` | 33 | CVE parsing, severity, dedup, URL linking, collector, honest UA |
| `tests/unit/test_nuclei_network.py` | 28 | Network-template parsing, non-web targeting, collector |
| `tests/unit/test_pipeline_phases.py` | 1 | Phase ordering sanity |
| `tests/unit/test_qcluster_config.py` | 4 | Django-Q cluster config |
| `tests/unit/test_reports.py` | 51 | CSV export content/structure, PDF export (WeasyPrint, mocked via _render_pdf), min_severity filter, per-severity count aggregation, issue grouping, scope/CWE/CVSS/risk enrichment, WAF coverage block, technology stack block |
| `tests/unit/test_waf_detection.py` | 16 | WAF/block/challenge classifier (spec C1) — vendor fingerprint, false-positive guards, analyzer wiring |
| `tests/unit/test_coverage.py` | 6 | Scan coverage (spec C2) — endpoint counts, dominant vendor, report note wording |
| `tests/unit/test_scans.py` | 30 | ScanSession, scheduling, scan_start views |
| `tests/unit/test_scheduler.py` | 33 | reap_stuck_scans, token purge, daily_scan, authorization gate, `SCHEDULED_SCANS_ENABLED` switch |
| `tests/unit/test_service_detection.py` | 64 | XML parsing, Port enrichment, is_web |
| `tests/unit/test_ssh_checker.py` | 34 | SSH probe, host key, kex/cipher/MAC, auth, collector |
| `tests/unit/test_subfinder.py` | 10 | JSON parser, dedup, hostname normalization |
| `tests/unit/test_subscan.py` | 12 | Targeted re-scan of a single tool / subset |
| `tests/unit/test_takeover_check.py` | 35 | collector (missing binary, bad JSON, happy path), analyzer (vulnerable/non-vulnerable, FK link, dedup), scanner |
| `tests/unit/test_tls_checker.py` | 87 | Cert parsing, ciphers, protocols, HSTS, collector, scanner, cipher enumeration |
| `tests/unit/test_tools_healthcheck.py` | 14 | Tool binary preflight / health checks |
| `tests/unit/test_user_profile.py` | 7 | UserProfile `must_change_password` flag |
| `tests/unit/test_settings_security.py` | 16 | SECRET_KEY strength guard (DEBUG=False + insecure default) |
| `tests/unit/test_insights_builder.py` | 4 | FindingTypeSummary prune only when aggregation_complete |
| `tests/unit/test_web_checker.py` | 40 | Headers, cookies, CORS, disclosure, collector |
| `tests/unit/test_passive_scan.py` | 21 | registry `active` classification, `is_passive_tool_set`, Passive Scan workflow all-passive invariant, passive-scan auth-gate bypass + active-scan gate, subscan gate |
| `tests/unit/test_workflow_runner.py` | 33 | run_workflow, naabu-gated service_detection injection, step failure, cancellation, phase parallelism |
| `tests/unit/test_default_workflow.py` | 5 | Full Scan is the default workflow with the complete 18-tool set (migration 0021), idempotent gap-fill |
| `tests/integration/test_scan_flow.py` | 12 | Full pipeline (mocked) + delete cascade |
| `tests/unit/test_update_check.py` | 22 | Update-available check — version parse/compare, cached GitHub fetch, fail-graceful on timeout/HTTP-error/bad-payload, endpoint shape |
| `tests/unit/test_proc_env.py` | 4 | `go_memory_env()` — GOMEMLIMIT/GOGC set in low profile, unchanged otherwise, preserves existing env |
| `tests/unit/test_coverage_regression.py` | 10 | Silent-block coverage counting (probed-vs-reached), coverage-regression finding (high block ratio / findings drop / stable = no flag), partial scan status when a tool fails |
| `tests/test_api_endpoints.py` | 104 | Smoke tests for all API endpoints (auth + payload shape), incl. build-provenance `/health/` + `/api/version/` (+ `no-store`) + update-check `/api/version/latest/` |

**Total: 1341 tests** (1289 fast + 52 slow domain_security)
