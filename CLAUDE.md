# CLAUDE.md — OpenEASD Django Project

External Attack Surface Detection platform. Scans domains for network and
web vulnerabilities using a dynamic workflow engine with auto-registered tools.

## Status (v2.12.0 — 2026-09-10)

- **Released**: v2.12.0 — images `ghcr.io/cybersecify/openeasd-{web,worker}` at
  `:v2.12.0` / `:v2.12` / `:latest` (web on python:3.12-slim, worker on Ubuntu 24.04/3.12 — both Python 3.12; Django 5.2 LTS). 3-tier deploy: `db` (postgres:17) + `web`
  (gunicorn, no tools) + `worker` (`dbos_worker` + scanner matrix, `NET_RAW`).
- **Scope**: 29 registered scan tools across 12 pipeline phases; single-user
  (one admin, no RBAC) by design.
- **Engine**: DBOS durable workflows on PostgreSQL — one multi-step `run_scan`
  workflow per scan (checkpoint/resume) + `@durable_task` for one-step tasks
  (`ai_triage`, `agent_step`) + `@scheduled` crons. No SQLite, no Django-Q/Celery.
- **AI**: optional Cloudflare Workers AI layer (BYOK, off by default, consent-gated).
- **Docs**: [`docs/DESIGN.md`](docs/DESIGN.md) (architecture — layers/tiers,
  workflow-vs-pipeline, apps), [`docs/DECISIONS.md`](docs/DECISIONS.md) (why),
  [`docs/PRD.md`](docs/PRD.md) (product), `docs/specs/` (feature specs +
  producer→queue→consumer hardening plan H1–H7). Release notes: `CHANGELOG.md`.
- **Health**: `GET /health/` (unauth, K8s probes) · `GET /api/version/`.

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
- **4 jobs:**
  - `test` — ruff (lint), pytest (fast, excludes `test_domain_security.py`) against a **`postgres:17-alpine` service container** (DB_* env) with a **coverage gate** (`--cov-fail-under=80`; config in `[tool.coverage.run]`, ~83% currently), bandit (SAST), pip-audit (CVE scan)
  - `frontend` — `npm ci`, `npm run test:run` (Vitest + Testing Library, happy-dom env), `npm run build`
  - `docker` — matrix over the `web` + `worker` build targets, `docker buildx build` for `linux/amd64` (no push, cache check per target)
  - `publish` — matrix over `web` + `worker`; builds `linux/amd64` and pushes to `ghcr.io/cybersecify/openeasd-web` and `-worker`
- **Publish triggers:** every push to `main` (`:latest` tag) and `v*` git tags. A tag push emits both the full `:vX.Y.Z` (from `type=ref,event=tag`) and a floating `:vX.Y` major.minor tag (from `type=match,pattern=v\d+\.\d+`) so downstream can pin to a minor line and still get patch updates
- Runner: `ubuntu-24.04`, Python 3.12, `uv sync --group dev` for deps, `libcairo2-dev gcc libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0` system deps required (WeasyPrint PDF rendering)
- `pip-audit --ignore-vuln PYSEC-2025-183` — disputed PyJWT weak-key-length CVE, no fix available
- **Build provenance:** the `publish` job computes `OPENEASD_VERSION` (git tag for `v*`, else `pyproject.toml` version), `OPENEASD_GIT_SHA` (`github.sha`), and `OPENEASD_BUILD_DATE` (ISO UTC) and passes them as `build-args` to buildx. The Dockerfile bakes them into `ENV` (placed late so they never bust the cache of the heavy layers). Settings read them via `config()` with `dev`/`unknown` defaults for local runs. Surfaced at `GET /health/` + `GET /api/version/`, and shown as a muted footer on the login + change-password pages AND in the authenticated app sidebar (`frontend/src/components/BuildInfo.jsx`). The sidebar footer also does an "update available" check via `GET /api/version/latest/` (authenticated; compares the running build to the latest GitHub release, cached 6h, fail-graceful — logic in `apps/core/console/api/update_check.py`). The app never self-updates; it only surfaces a heads-up + release link.

## Commands
- Always use `uv run python` instead of `python` or `python3`
- Always use `uv run manage.py` for Django management commands (e.g. `uv run manage.py check`)
- Always use `uv run pytest` for running tests
- The slow `tests/unit/test_domain_security.py` (46 tests) makes real DNS/RDAP calls — exclude it for fast CI runs:
  `uv run pytest tests/ --ignore=tests/unit/test_domain_security.py`

## Stack

### Backend
- Django 5.2 LTS with plain Django views (no DRF, no Celery, no Redis) — pinned to
  the LTS line (`django>=5.2.17,<6.0`), not floated to non-LTS 6.x
- **Django Ninja** REST API under `/api/` — Schema-based, auto-docs at `/api/docs`
- **JWT Bearer auth** — access + refresh tokens via `djangorestframework-simplejwt` (ninja-jwt wrapper); token blacklist handled by simplejwt's built-in `OutstandingToken`/`BlacklistedToken` models
- **DBOS** — durable-execution engine for scan execution AND all scheduling, backed by PostgreSQL (its checkpoint tables live in a `dbos` schema in the same DB). Scans are durable workflows whose phases are checkpointed steps, so a crashed/restarted worker RESUMES a scan instead of losing it. Scheduling is DBOS `@scheduled` cron workflows (daily scan, monitoring sweep, user-schedule sweep, stuck-scan watchdog, JWT token purge) registered by the `dbos_worker` process. Django-Q2 and APScheduler have been fully removed.
- **WhiteNoise** — serves collected static files (frontend bundle) when `DEBUG=False` (Docker/prod); uses `CompressedManifestStaticFilesStorage` for gzip + content-hash fingerprinting
- **PostgreSQL** database — configured via `DB_HOST`/`DB_PORT`/`DB_NAME`/`DB_USER`/`DB_PASSWORD` (or `DATABASE_URL`). Postgres has no single-writer lock, so scans run concurrently (`DBOS_SCAN_CONCURRENCY`, default 2).

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

**Task runners:** both a `Makefile` and a `justfile` are provided with the same
recipes (`dev`, `worker`, `test`, `lint`, `migrate`, …) — use `make <target>` or
`just <target>` interchangeably. `just` adds a few extras: **`just ci`** runs the
whole CI pipeline locally (ruff + pytest w/ 80% coverage + bandit + pip-audit +
vitest + build — mirrors `.github/workflows/ci.yml`), and `just up`/`down`/`logs`/`ps`
drive the 3-container Docker Compose stack. `just` (no arg) lists all recipes.

```bash
# Quickest: starts Django (:8001) + Vite dev server + DBOS worker together
make dev        # or: just dev

# Or manually in three terminals:
# Terminal 1 — Django
uv run manage.py runserver 8001

# Terminal 2 — Vite dev server (proxies /api/ to Django at :8001)
cd frontend && npm install && npm run dev
# App runs at http://localhost:5173

# Terminal 3 — DBOS worker (required for scans to execute; needs PostgreSQL running)
uv run manage.py dbos_worker
```

### Frontend rules
- New interactive features → React pages in `frontend/src/pages/`, wired into the route tree in `src/router.jsx`
- Fetch data with react-query `useQuery` + `apiGet`/`apiPost` (keyed by the API path); don't reintroduce ad-hoc `fetch`/`useFetch`. Navigate with react-router-dom's `useNavigate`, not a hand-rolled router.
- New API data → add endpoint to the relevant `apps/core/<module>/api.py` router + wire in `apps/core/console/api/ninja.py`
- Shared UI primitives → `frontend/src/components/`
- Don't add CORS headers — always use same-origin (Vite proxy in dev, Django serves in prod)
- Legacy HTMX/Alpine/Django-template stack is **retired**. All UI is the React SPA.
- SPA catch-all in `openeasd/urls.py` serves `frontend/dist/index.html` for all non-API paths.
- Run `cd frontend && npm run build` to update the production bundle before deployment.

## Deployment

### Docker (production) — 3 services

The stack is **PostgreSQL + web + worker** (Option B) — the **recommended
architecture**: it keeps offensive tooling + `NET_RAW` off the internet-facing
`web` tier (privilege separation), isolates OOM-prone tool crashes to a worker
(the UI stays up), and lets workers scale independently of web. Collapsing
web+worker into one container is only for a small trusted single-user eval (it
puts tools + raw sockets on the exposed process); keep `db` separate regardless.
Use Docker Compose:

```bash
# Set real secrets in docker-compose.yml (SECRET_KEY, DB_PASSWORD, ALLOWED_HOSTS), then:
docker compose up -d --build
```
- `db` — `postgres:17-alpine` (app data + the DBOS `dbos` schema)
- `web` — `openeasd-web` image (`python:3.12-slim`): gunicorn, enqueue-only, no scanner tools
- `worker` — `openeasd-worker` image (`ubuntu:24.04`): `dbos_worker` + the full scanner matrix, `--cap-add NET_RAW`
- The entrypoint is role-aware (`OPENEASD_ROLE`): web migrates, worker waits for migrations then launches.
- **Two images** (`ghcr.io/cybersecify/openeasd-web` + `-worker`) — the web image carries no offensive tooling.
- `--cap-add NET_RAW` — required on the worker for nmap raw socket scanning
- `restart: unless-stopped` — survives server reboots
- **RAM: 2 GB min / 4 GB recommended.** nuclei + amass are memory-hungry and the
  kernel will OOM-kill them on an under-provisioned host (silent partial scans).
  `OPENEASD_PROFILE` (default `auto`, from RAM) tunes this: `low` (<2GB or
  `OPENEASD_LOW_MEMORY=true`) runs tools sequentially + throttles nuclei + skips
  amass brute so ~1GB completes without OOM; `balanced` (2-8GB) is the old
  default; `high` (≥8GB) raises LOCAL concurrency. **Exception:** a phase group
  of only light, network-I/O-only tools (`runner._LOW_MEM_PARALLEL_SAFE` —
  domain_security/domain_probe/typosquat/dns_history/hudson_rock/breach_check/
  github_secrets) runs concurrently *even under low memory* (they never OOM like
  nuclei/amass), so the phase-1 intelligence group stays fast on a 1GB box;
  override via `SCAN_LOW_MEM_PARALLEL_SAFE`. `typosquat` also resolves its
  candidates and probes homepages concurrently (`TYPOSQUAT_DNS_CONCURRENCY`=16 /
  `TYPOSQUAT_FETCH_CONCURRENCY`=8) instead of serially. Per-target request rate stays
  capped across all profiles (politeness — a big box is no licence to hammer the
  target; higher rates just trip WAFs, which the coverage report flags). Add
  swap on 1GB hosts. Resolver + tuning in settings/base.py (`_resolve_profile`,
  `_PROFILE_TUNING`). nuclei is also severity-scoped per profile (`NUCLEI_SEVERITY`;
  low=critical/high/medium, else +low; `info` dropped everywhere) — the fix for
  its freeze/timeout since it compiles all ~13.5k templates into RAM. See
  `docs/SCAN_OPERATIONAL_LEARNINGS.md`.
- Volumes: PostgreSQL data (its own volume/PVC) and `openeasd-logs` persist across container replacements; app data lives in Postgres, not a file
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

**Layout — 3 tiers, each its own workload (matches the docker-compose 3-tier):**
```
Deployment openeasd-web     → initContainer init (migrate + collectstatic + admin, docker-entrypoint.sh),
                              then gunicorn openeasd.wsgi:application --bind 0.0.0.0:8000 --workers 2
                              (no NET_RAW; logs to stdout; the Service targets tier: web)
Deployment openeasd-worker  → ./docker-entrypoint.sh python manage.py dbos_worker with OPENEASD_ROLE=worker
                              (waits for `migrate --check`, then runs scan/AI/@scheduled workflows; NET_RAW)
StatefulSet openeasd-postgres → PostgreSQL (see k8s/postgres.yaml)
```
So a default deploy is **3 pods** (web, worker, postgres). web and worker are
separate Deployments so they scale, roll, and get resources independently; only
the worker needs `NET_RAW`, and the internet-facing web tier carries no
raw-socket capability. Migrations run only in the web Deployment's initContainer;
the worker waits for them via the role-aware entrypoint (no DDL race).

**Files:**
```
k8s/
  configmap.yaml         — non-secret env vars; ALLOWED_HOSTS/CSRF are PLACEHOLDERS only
  secret.yaml            — template for SECRET_KEY + real ALLOWED_HOSTS/CSRF (apply out-of-band)
  postgres.yaml          — PostgreSQL StatefulSet + headless Service + 10Gi PVC
  web-deployment.yaml    — openeasd-web: init + web (tier: web, no NET_RAW, stdout logs)
  worker-deployment.yaml — openeasd-worker: DBOS worker (tier: worker, NET_RAW, no Service)
  service.yaml           — NodePort 30808 → 8000, selector tier: web ONLY
  ingress.yaml           — nginx Ingress; TLS annotations ready to uncomment
  kustomization.yaml     — kubectl apply -k k8s/ (does NOT include secret.yaml)
```

**Key constraints:**
- `replicas: 1` on each Deployment by default. Postgres removes the SQLite single-writer limit, so `openeasd-worker` can scale to multiple replicas pulling the same DBOS queue (`kubectl scale deploy/openeasd-worker --replicas=N`) independently of `openeasd-web`
- Only `openeasd-worker` gets `NET_RAW`; `openeasd-web` does not need it
- Logs go to **stdout** (`kubectl logs`) — no logs PVC (so nothing blocks a rolling update)
- The Service selector is `app: openeasd, tier: web` — it must NOT match the worker (which shares `app: openeasd` but has no :8000 listener)
- `GET /health/` — unauthenticated endpoint used by K8s readiness/liveness probes; JSON body is `{status, version, git_sha (short 8), build_date}` (build provenance)
- **Real `ALLOWED_HOSTS`/`CSRF_TRUSTED_ORIGINS` live in `openeasd-secret`, never in
  the committed configmap.** `configmap.yaml` carries only placeholders; the real
  hostname is set in the secret, which is applied out-of-band and is intentionally
  omitted from the kustomize base. Because each deployment's `envFrom` lists
  `secretRef` after `configMapRef` (last source wins), the secret's values override
  the configmap placeholders at runtime. This is deliberate: it keeps the real host
  out of the public repo AND makes `kubectl apply -k k8s/` safe — a re-apply can
  never clobber `ALLOWED_HOSTS` back to the placeholder and 400 the live host.
  Set them when creating the secret (see `k8s/secret.yaml` and `kustomization.yaml`).

**Update running deployment:**
```bash
kubectl rollout restart deployment/openeasd-web deployment/openeasd-worker -n default
```

### docker-entrypoint.sh
Runs on every container start (init container in K8s, or `CMD` override in Docker):
1. `manage.py migrate --run-syncdb`
2. `manage.py collectstatic --noinput --clear`
3. Creates `admin/admin` with `must_change_password=True` if no users exist; re-flags if default password still in use
4. `exec "$@"` — hands off to the actual process

### First login
`docker-entrypoint.sh` is role-aware (`OPENEASD_ROLE`): both roles wait for PostgreSQL; the web/init role runs migrate + collectstatic + admin setup (creating `admin/admin` with `must_change_password=True` on first run, re-flagging if the default password is still in use), while the worker role waits for `migrate --check` to pass then launches (no DDL race). The React app redirects to `/change-password` before allowing access.

### microk8s deployment (host IP changed)
If the host IP changes, microk8s certs and kubeconfigs reference the old IP and the cluster goes "not running":
1. Update IP-SAN in `/var/snap/microk8s/current/certs/csr.conf.template` (the `IP.3` line), then `sudo microk8s refresh-certs --cert server.crt`.
2. `refresh-certs` does **not** rewrite the client kubeconfigs — sed-replace the old `server: https://<old-ip>:16443` in `/var/snap/microk8s/current/credentials/{client,kubelet,controller,scheduler,proxy}.config`.
3. `refresh-certs` also does **not** cover `kubelet.crt` (the kubelet's serving cert) — regenerate it manually with openssl, signed by `ca.crt`/`ca.key`, with Subject `CN=system:node:<hostname>, O=system:nodes` and SANs `DNS:<hostname>, IP:<new-host-ip>, IP:127.0.0.1`. Without this, `kubectl logs`/`exec` fail with "certificate is valid for <old-ip>".
4. Restart with `sudo microk8s stop && sudo microk8s start` (or just `systemctl restart snap.microk8s.daemon-kubelite` if only kubelet.crt changed).
5. Backups from `microk8s refresh-certs` land in `/var/snap/microk8s/<rev>/certs-backup/`; manual kubelet regen leaves `kubelet.crt.bak.<epoch>` next to the new cert.

### microk8s + host Caddy
Don't enable the `ingress` addon if the host already runs Caddy on :80/:443 — the nginx-ingress DaemonSet uses `hostPort` 80/443, and CNI portmap iptables intercept all traffic in PREROUTING before it reaches Caddy, silently breaking every Caddy site. Instead: expose the service as `NodePort` (e.g. 30808) and have Caddy `reverse_proxy localhost:<nodeport>`. The probe still needs `httpHeaders: [{name: Host, value: <ALLOWED_HOSTS-entry>}]` because kubelet sends the pod IP as Host by default and Django rejects it with 400. **That probe Host (`openeasd.local` in `web-deployment.yaml`) must be present in `openeasd-secret`'s `ALLOWED_HOSTS`, not just the configmap** — the secret's `ALLOWED_HOSTS` overrides the configmap's (`secretRef` is last in `envFrom`), so a secret listing only the real host drops `openeasd.local` and the probes 400 → the pod never goes Ready. Keep it in the secret (see `k8s/secret.yaml`).

### Scheduler
- Daily scan runs at `SCAN_DAILY_HOUR:SCAN_DAILY_MINUTE` (uses `TIME_ZONE` in settings, default 02:00)
- Configured via env vars: `SCAN_DAILY_HOUR`, `SCAN_DAILY_MINUTE`
- **Auto-scan consent gate:** `daily_scan` and per-domain monitoring only scan domains with a `DomainAuthorization` record (`is_active=True, authorization__isnull=False`); `run_monitoring_scan` re-checks at run time. The scheduler cannot bypass the authorization gate the manual API/UI already enforce. (Scheduled scans always run the default active Full Scan workflow, so the gate always applies to them — the passive-scan exemption below is manual/`now`-only.)
- **`SCHEDULED_SCANS_ENABLED`** (env, default `True`) is the master switch for unattended scanning. When `False`, `setup_core_schedules()` registers only the hygiene jobs (watchdog + token purge) and removes any existing `daily_scan`/`monitor_*` schedules on startup — this is how a deployment is made durably manual-only (set in `k8s/configmap.yaml`). Manual/API scans are unaffected.
- Schedule history visible in Django admin under "Django Q" → "Scheduled tasks"
- Scheduler code lives in `apps/core/engine/scheduler/scheduler.py`
- `setup_core_schedules()` called from `apps/core/engine/scheduler/apps.py` → `SchedulerConfig.ready()`
- The DBOS `@scheduled` cron workflows register only in the `dbos_worker` process (they are decorators applied when the worker imports `apps/core/engine/durable/workflows`) — never in gunicorn workers

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

### Core infrastructure — `apps/core/` (16 sub-apps)

The 16 core apps are grouped into layer subpackages: **`apps/core/console/`**
(dashboard, insights, reports, notifications, ai, credentials, api), **`apps/core/engine/`**
(scans, workflows, durable, scheduler, service_detection), and
**`apps/core/data/`** (domains, assets, web_assets, findings, asset_inventory).
Django labels are unchanged — the nesting is organisational only (import paths are
`apps.core.<layer>.<app>`). See `docs/DESIGN.md` for the layer model.

| App | Label | Purpose |
|---|---|---|
| `dashboard/` | `core` | Dashboard page, health check; **UserProfile** model (`must_change_password` flag) |
| `domains/` | `domains` | Domain model, CRUD views |
| `assets/` | `assets` | Network assets: Subdomain, IPAddress, Port |
| `web_assets/` | `web_assets` | Web assets: URL |
| `service_detection/` | `service_detection` | Enriches Port.service + Port.is_web via nmap -sV |
| `findings/` | `findings` | Unified Finding model — all tools write here |
| `asset_inventory/` | `asset_inventory` | Persistent, deduplicated `Asset` inventory (domain-scoped, first/last-seen + status) — populated by a fail-graceful rollup at finalize; `Finding.asset` links findings to it. Spec: `docs/specs/2026-09-06-asset-centric-inventory.md` (PR1: model + rollup + backfill) |
| `scans/` | `scans` | ScanSession, ScanDelta, pipeline orchestrator |
| `workflows/` | `workflow` | Workflow CRUD, dynamic runner, tool registry |
| `scheduler/` | `scheduler` | Scan callables (daily_scan, run_due_monitoring_scans, run_due_user_scans, reap_stuck_scans, token purge) invoked by the DBOS `@scheduled` workflows in `apps/core/engine/durable` |
| `notifications/` | `alerts` | Slack/Teams alerts, NotificationConfig model, alert history |
| `insights/` | `insights` | ScanSummary (incl. per-scan Exposure Score + grade, `scoring.py`), FindingTypeSummary, charts |
| `reports/` | `reports` | CSV + PDF export (synchronous, served by the web tier) |
| `ai/` | `ai` | AI analysis (Cloudflare Workers AI, BYOK): finding triage, bounded adaptive orchestration, report/alert summaries, consent + per-call audit log |
| `credentials/` | `credentials` | UI-managed BYOK API keys — `ToolCredentials` encrypted singleton + `get_credential()` resolver (DB-wins-over-env) + write-only `/api/credentials/` + the `/credentials` **CredentialsPage**. Tools read via the resolver (shodan/breach_check/github_recon/github_secrets/dns_history) — a DB key overrides env with no redeploy |
| `api/` | — | Django Ninja API — routers, JWT auth, error handlers |

### REST API module — `apps/core/console/api/`

```
apps/core/console/api/
    __init__.py
    ninja.py          — NinjaAPI instance, ninja-jwt auth routes (/token/pair|refresh|verify|blacklist),
                        /user/ endpoint, error handlers, router registration

Per-module routers (each file exports a `router = Router(auth=JWTAuth())`):
    apps/core/console/dashboard/api.py   — /api/dashboard/
    apps/core/data/domains/api.py     — /api/domains/ CRUD
    apps/core/engine/scans/api.py       — /api/scans/ + findings
    apps/core/engine/workflows/api.py   — /api/workflows/ CRUD + /tools/
    apps/core/console/insights/api.py    — /api/insights/
    apps/core/console/notifications/api.py — /api/notifications/ config + test + alerts
    apps/core/console/credentials/api.py — /api/credentials/ (write-only BYOK key store)
    apps/core/data/asset_inventory/api.py — /api/assets/ list + summary + detail
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
- **Brute-force rate limiting:** `LoginRateLimitMiddleware` (`apps/core/console/api/ratelimit.py`) locks out an IP after `LOGIN_RATELIMIT_MAX_FAILURES` (default 5) failed `POST /api/token/pair` attempts within the window, returning 429 + `Retry-After`. State is the DB-backed `LoginThrottle` model (shared across gunicorn workers, unlike the per-process LocMemCache). Only `/token/pair` is limited (not `/refresh`); a successful login clears the IP's counter. Per-IP via `X-Forwarded-For` when `LOGIN_RATELIMIT_TRUST_FORWARDED_FOR` is on (default, for the mandated proxy); off → falls back to the unspoofable `REMOTE_ADDR` so a bare deployment can't be evaded by rotating the header. Tunable/`LOGIN_RATELIMIT_ENABLED`-toggle via settings. Tests: `tests/unit/test_login_ratelimit.py`.

**Adding a new API endpoint:**
1. Add endpoint function to the relevant `apps/core/<module>/api.py` router
2. Register the router in `apps/core/console/api/ninja.py` if it's a new module
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

The registry (`apps/core/engine/workflows/registry.py`) auto-discovers all `tool_meta` at startup and provides:
- `get_tool_choices()` — for forms and UI
- `get_tool_runners()` — for workflow execution
- `get_tool_phases()` — for ordering
- `get_tool_phase_groups()` — maps tool → phase_group label
- `get_tool_requires()` — for dependency validation
- `get_source_choices()` — for finding source filtering

**Pipeline diagram (generated, drift-proof):** `manage.py render_pipeline_diagram`
renders the whole pipeline — every phase group, tool, passive/active flag, and
dependency — straight from the registry as self-contained HTML (`-o file.html`),
a terminal tree (`--format text`), or JSON (`--format json`). Because it reads
`tool_meta` live, it can never drift; a test (`test_render_pipeline_diagram.py`)
guards that every registered tool appears in the output.

### Tool apps (29 registered tools)

| App | Phase | Phase Group | produces_findings | Description |
|---|---|---|---|---|
| `apps/domain_security/` | 1 | Domain Intelligence | Yes | **Passive** DNS/DNSSEC/CAA/wildcard/lame-delegation, email-auth (SPF/DMARC/DKIM/TLS-RPT/BIMI) via public resolvers, and RDAP (expiry/locks/status). No packets to the target — needs no authorization |
| `apps/domain_probe/` | 1 | Domain Intelligence | Yes | **Active** domain probes split out of domain_security: AXFR zone transfer (nameservers), SMTP open-relay (MX:25), and MTA-STS policy fetch (`mta-sts.<domain>`). Touches the target directly → requires `DomainAuthorization` |
| `apps/hudson_rock/` | 1 | Data Leak | Yes | Infostealer-log exposure via Hudson Rock's keyless Cavalier API (aggregate counts only, no plaintext); passive, fail-graceful |
| `apps/dns_history/` | 1 | Domain Intelligence | Yes | Historical A/AAAA/MX records via a passive-DNS dataset — surfaces past hosting / stale records (info findings). Passive, BYO `DNS_HISTORY_API_URL` (no-op if unset), fail-graceful |
| `apps/github_secrets/` | 1 | Data Leak | Yes | Leaked secrets in PUBLIC GitHub — searches GitHub's code-search API (org-scoped by default) for the target org's committed credentials, fetches the hits, runs gitleaks over them (same engine as `js_secrets`), REDACTS before storage (`check_type="exposed_secret"`, shared with js_secrets). Passive (queries GitHub, not the target); BYOK MANDATORY (`GITHUB_TOKEN` — code-search needs auth; no token → logged no-op); fail-graceful |
| `apps/typosquat/` | 1 | Domain Intelligence | Yes | Lookalike / typosquat domain detection — generates lookalike candidates algorithmically (homoglyph/typo/omission/insertion/repetition/transposition/hyphenation/TLD-swap), checks which are registered via public DNS, then scores **weaponization**: registered web-serving lookalikes get a capped, fail-graceful homepage fetch for a login form (credential phishing) or brand mention (impersonation) → **high** (active impersonation, prioritise takedown); A/MX-only → medium; NS-only → low. Passive w.r.t. the target (contacts only the lookalike domains, never yours), no key, fail-graceful. Weaponization model ported from the standalone `tldsquatting` project |
| `apps/breach_check/` | 1 | Data Leak | Yes | Data-breach exposure for the domain. BYOK: free keyless XposedOrNot catalog by default, authoritative Have I Been Pwned `breacheddomain` when `HIBP_API_KEY` set. Aggregate COUNTS + public breach metadata only — never email aliases/credentials. Passive, fail-graceful |
| `apps/subfinder/` | 2 | Surface Enumeration | No | Passive subdomain enumeration |
| `apps/amass/` | 2 | Surface Enumeration | No | Active subdomain enumeration |
| `apps/asn_discovery/` | 2 | Surface Enumeration | Yes | Owned ASN / CIDR discovery via `amass intel` (passive registry/BGP recon); reports ranges only, no auto-scan expansion |
| `apps/alterx/` | 2 | Surface Enumeration | No | Subdomain permutation via alterx (generates candidates from discovered subdomains) |
| `apps/github_recon/` | 2 | Surface Enumeration | Yes | GitHub Org Recon — enumerates the target org's PUBLIC GitHub repos via GitHub's official REST API and surfaces exposed infra references (internal hostnames/subdomains, cloud-bucket URLs, API endpoints) in that public code/config. Two-tier BYO-token: keyless unauthenticated API (60 req/hr, request-capped) works out of the box, `GITHUB_TOKEN` raises to 5000 req/hr. Complements `js_secrets`/`github_secrets` (secrets) — this finds infra exposure. Passive (queries GitHub, never the target), fail-graceful |
| `apps/dnsx/` | 3 | Surface Enumeration | No | DNS resolution, public IP filtering |
| `apps/takeover_check/` | 4 | Surface Enumeration | Yes | Subdomain takeover detection via subzy (dangling DNS → unclaimed cloud) |
| `apps/cloud_assets/` | 4 | Surface Enumeration | Yes | Public cloud bucket enumeration via cloud_enum (AWS S3 / Azure Blob / GCP Storage) |
| `apps/naabu/` | 5 | Port Discovery | No | Port scanning (top 100 TCP) |
| `apps/shodan/` | 5 | Port Discovery | Yes | Passive exposure intel from Shodan's own scan data — ports/services/CVEs per resolved IP. BYOK: free InternetDB tier (no key, no credits), full host API when `SHODAN_API_KEY` set (`SHODAN_MAX_IPS` caps the paid path). CVEs land in `extra["cve_ids"]` so `cve_intel` enriches them. Passive, fail-graceful |
| `apps/core/engine/service_detection/` | 6 | Port Discovery | No | nmap -sV enriches Port.service + is_web |
| `apps/nmap/` | 7 | Network Exposure | Yes | NSE vulners CVE scan (non-web ports); backport-aware CVE matching (`backports.json` registry) |
| `apps/tls_checker/` | 7 | Network Exposure | Yes | TLS/cert analysis + cipher suite enumeration via `nmap --script ssl-enum-ciphers` (all ports) |
| `apps/ssh_checker/` | 7 | Network Exposure | Yes | SSH config analysis |
| `apps/nuclei_network/` | 7 | Network Exposure | Yes | Network protocol vuln scan (319 templates, non-web) |
| `apps/httpx/` | 8 | Web Exposure | No | Web probing, URL discovery, technology fingerprinting (`-tech-detect` → `URL.technologies`) |
| `apps/historical_urls/` | 9 | Web Exposure | No | Historical URL discovery via gau (Wayback Machine, OTX, Common Crawl, URLScan) |
| `apps/katana/` | 10 | Web Exposure | No | Web crawling, endpoint discovery |
| `apps/nuclei/` | 11 | Web Exposure | Yes | Web vuln scan (community templates) |
| `apps/web_checker/` | 11 | Web Exposure | Yes | Security headers, cookies, CORS; + security.txt (RFC 9116) responsible-disclosure check on the apex |
| `apps/js_secrets/` | 11 | Data Leak | Yes | Hardcoded-secret detection — fetches discovered `.js` assets and runs gitleaks over them; secret is redacted before storage |
| `apps/cve_intel/` | 12 | Prioritization | No | Enriches CVE findings in place with EPSS scores + CISA KEV flags (no new findings) |

### Tool app structure
```
apps/<tool>/
    apps.py         — AppConfig with tool_meta (self-registration)
    models.py       — empty (writes to apps/core/data/assets/ and apps/core/data/findings/)
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
Phase 1  domain_security    → Finding (DNS/DNSSEC/email-auth/RDAP — passive)
Phase 1  domain_probe        → Finding (AXFR / open-relay / MTA-STS fetch — active)
Phase 1  hudson_rock         → Finding (infostealer exposure via Hudson Rock — passive)
Phase 1  dns_history         → Finding (historical A/AAAA/MX records via passive DNS — passive)
Phase 1  github_secrets      → Finding (leaked secrets in public GitHub via gitleaks — passive, BYO token)
Phase 1  typosquat           → Finding (registered lookalike/typosquat domains via public DNS — passive)
Phase 1  breach_check        → Finding (data-breach exposure: XposedOrNot free / HIBP BYO-key — passive, counts only)
Phase 2  subfinder          → Subdomain (passive enumeration)
Phase 2  amass              → Subdomain (active enumeration)
Phase 2  asn_discovery      → Finding (owned ASN/CIDR ranges via amass intel — informational)
Phase 2  alterx             → Subdomain (permutation candidates from existing subdomains)
Phase 2  github_recon       → Finding (infra refs in the org's PUBLIC GitHub repos — passive)
Phase 3  dnsx               → IPAddress (public-only filter)
Phase 4  takeover_check     → Finding (subzy — dangling DNS → unclaimed cloud)
Phase 4  cloud_assets       → Finding (open S3/Azure/GCP buckets — cloud_enum)
Phase 5  naabu              → Port (top 100 TCP scan)
Phase 5  shodan             → Finding (passive exposure: ports/services/CVEs from Shodan's data)
Phase 6  service_detection  → enriches Port.service + Port.is_web
Phase 7  nmap               → Finding (CVEs on non-web ports, is_web=False)  ┐
Phase 7  tls_checker        → Finding (cipher/cert/protocol on all ports)    │ parallel
Phase 7  ssh_checker        → Finding (SSH config on service="ssh" ports)    │
Phase 7  nuclei_network     → Finding (network protocol vulns, non-web ports)┘
Phase 8  httpx              → URL (web probing, CDN-aware via SNI)
Phase 9  historical_urls    → URL (gau — archived endpoints)
Phase 10 katana             → URL (web crawling, endpoint discovery)
Phase 11 nuclei             → Finding (web vulns via templates on URLs)
Phase 11 web_checker        → Finding (headers, cookies, CORS on URLs; + security.txt RFC 9116 on apex)
Phase 11 js_secrets         → Finding (gitleaks over fetched .js assets — secret redacted)
```

### Passive vs active scan modes (the authorization boundary)

Every tool carries an `"active": True/False` flag in its `tool_meta`, exposed by
the registry via `get_tool_active()` and `is_passive_tool_set(tools)`.

- **Passive** (`active=False`): uses ONLY public / third-party data — CT logs and
  other subdomain feeds, DNS resolution via public resolvers, WHOIS/RDAP, web
  archives, cloud-provider bucket APIs, Shodan's own scan dataset, CVE/EPSS/KEV
  feeds. Sends **no packets to the target's own systems**. Needs **no
  `DomainAuthorization`**.
  Passive tools: `domain_security`, `subfinder`, `alterx`, `dnsx`,
  `historical_urls`, `cloud_assets`, `cve_intel`, `asn_discovery`, `hudson_rock`,
  `shodan`, `typosquat`, `breach_check`, `github_secrets`, `github_recon`,
  `dns_history`.
- **Active** (`active=True`): probes the target directly (port scans, HTTP/TLS/SSH
  connections, crawling, vuln templates, AXFR/SMTP/mta-sts probes). **Requires
  `DomainAuthorization`.**
  Active tools: `domain_probe`, `amass`, `takeover_check`, `naabu`,
  `service_detection`, `nmap`, `tls_checker`, `ssh_checker`, `nuclei_network`,
  `httpx`, `katana`, `nuclei`, `web_checker`.

**Default is active.** `tool_meta` omitting `"active"` is treated as active — a
missing flag can never let a scanner probe an unauthorized target.

**`domain_security` is now passive; its active probes live in `domain_probe`.**
The passive tool does DNS/DNSSEC/CAA/email-auth via public resolvers and RDAP via
rdap.org — no packets to the target. The active probes that DO touch the target —
AXFR zone transfers, SMTP open-relay, and the MTA-STS policy-file fetch — were
split into `apps/domain_probe` (active). A tool with ANY code path that touches
the target is active; keeping those paths isolated lets the passive DNS/email/RDAP
intelligence run in a no-auth passive scan.

**Authorization rule (`apps/core/engine/scans/api.py`):** a `schedule_type="now"` scan
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
  → run_scan_task(session_id)        # durably enqueues the DBOS run_scan workflow
    → run_scan(session_id)           # sets status="running"
      → _run_via_workflow(session)   # creates WorkflowRun, calls run_workflow()
        → run_workflow(run_id)       # loops enabled tools, records StepResults
      → _finalize_session(session)   # count findings → coverage → status
          → _detect_deltas / _check_coverage_regression / build_insights
          → run_ai_post_scan(session)     # AI triage + summaries (no-op unless keys+consent)
          → _dispatch_alerts(session)     # Slack/Teams (carries the AI alert summary)
          → maybe_start_agent(session)    # queues the bounded orchestration agent
```

### AI layer flow (apps/core/console/ai — runs only when keys + enabled + consent)
```
_finalize_session
  → run_ai_post_scan(session)              # INLINE in the scan task, before alerts
      → run_triage(session)                # ranks findings by EXPLOITABILITY
      │     context: CVSS + EPSS + CISA-KEV (cve_intel enrichment) + exposure
      │     → AITriage + AITriageItem (priority: fix_now/plan/monitor/likely_noise)
      → run_summaries(session)             # AISummary rows: report + alert kinds
  → maybe_start_agent(session)             # CHAINED DBOS agent_step workflows, after alerts
      → _run_agent_step(root_session)      # ONE LLM decision per step:
            run_subscan(tools) ─ gate_subscan_tools() re-checks DomainAuthorization
              → create_subscan_session(triggered_by="agent") → run_scan_task()
              → that subscan's _finalize_session → maybe_continue_agent() → next step
            flag_finding(id)   ─ AgentAction marker only (never mutates Finding.status)
            done(summary)      ─ AgentRun terminal
      # bounded: ≤ max_agent_iterations, ≤ max_subscans_per_scan, per-scan call budget

every Cloudflare call → AIInvocation audit row (metadata only, never prompt/response bodies)
```

### Key design rules
1. **Tools never import from each other.** Shared data flows through `apps/core/data/assets/`, `apps/core/data/web_assets/`, and `apps/core/data/findings/`.
2. **Tools self-register.** Add `tool_meta` to AppConfig + add to `INSTALLED_APPS`. No other core files to touch.
3. **Port.is_web** classifies ports. Set by `service_detection` (Phase 6) based on nmap -sV service name. Used by nmap to skip web ports (`is_web=False` only). tls_checker probes all ports — including HTTPS (port 443).
4. **dnsx filters to public IPs only.** Private/loopback/link-local/AWS metadata IPs dropped.
5. **httpx feeds subdomain:port pairs, not IP:port pairs.** Cloudflare/CDN-fronted services need SNI matching.
6. **nmap only scans non-web ports** (`Port.objects.filter(is_web=False)`).
7. **Asset deletion cascades:** Subdomain → IPAddress → Port → URL. Deleting a Domain wipes all session data.
8. **Delta detection** compares ALL findings between current and previous scan for the same domain.

### Pipeline + workflow rules

The architecture is a **pipeline** (12 phases) built out of **durable workflows**
(DBOS). Pipeline outside, workflows inside, Postgres between them. These are the
same 14-point rules the sibling `cybersecify/backend` follows; OpenEASD adopts the
foundational ones and consciously differs on the *choreography* ones (it's
**orchestrated** — one workflow-per-scan — because the dataflow is fixed). Each
row notes OpenEASD's stance. Full plan + status: `docs/specs/2026-09-07-producer-queue-consumer-hardening.md`.

**Design**
1. **Draw the pipeline before writing a workflow** — name the phase, the rows it stores, what triggers the next. ✅ (12 phases in DESIGN.md)
2. **Stages talk through stored data, never workflow calls** — a tool writes rows, the next phase reads them. ✅ (the empty-`models.py` rule)
3. **One workflow per unit of work** — ⚠️ *deliberate deviation*: OpenEASD runs one multi-step `run_scan` per scan (orchestrated), not per-unit; retry granularity is per phase-group (checkpointed step).
4. **Every workflow idempotent** (delete-then-insert / upsert, not append) — 🟡 partial: alerts ✅ (H1), phase-step idempotency is **H5**.
5. **Every workflow has an identity key** — ✅ `deduplication_id` (`scan-{id}`, `triage-{id}`) + `dedupe=` on `@durable_task`.

**Triggering**
6. **Trigger the next stage from the write, not the caller** — ⚠️ *deviation*: phases are orchestrator-driven, not write/signal-triggered (the AI-agent chain is the one hook-triggered path).
7. **Gate automatic triggers by freshness** — 🟡 `SCHEDULED_SCANS_ENABLED` + monitoring intervals.
8. **Every timed job in one editable table** — 🟡 user scans in `ScheduledScan`; system crons are `@DBOS.scheduled` in code → **H7** (`ScheduledJob` table).

**Running**
9. **Route by resource, not stage** — ⚠️ *deviation*: single `scans` queue (no scarce GPU-like resource to isolate).
10. **Fail whole, retry whole** — 🟡 *deliberate variation*: OpenEASD delivers **labeled partials** (a time-boxed scan is a valid result; a failed tool → `partial`, never fake-complete).
11. **Keep the engine behind an adapter** — ✅ `@durable_task` (H6); DBOS isolated to `apps/core/engine/durable/`.

**Operating**
12. **Every stage: safety net + alarm** — 🟡 scan-level watchdog (`reap_stuck_scans`) + sweeps; per-stage + alarm is **H4**.
13. **Measure the whole journey, not each run** — ❌ **H2** (`/metrics` + enqueue→output timing) pending.
14. **Rehearse the failure** — 🟡 crash-resume is tested (D-016), no prod chaos drill yet.

## Unified Finding model

`apps/core/data/findings/Finding` — all tools write to it:

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

**JSON-field aggregation:** the codebase groups JSON-extracted fields (e.g. `extra__cvss_score`) in Python rather than via `Max(...)` DB aggregation — a habit from the former SQLite backend. PostgreSQL supports these aggregations natively, but the Python-side grouping is kept for portability; no need to "fix" it.

## Secrets at rest — `apps/core/crypto.py` + `apps/core/fields.py`

BYOK credentials stored in the DB are **encrypted at rest** via
`EncryptedCharField`/`EncryptedTextField` (transparent Fernet encrypt-on-write /
decrypt-on-read; TEXT column; blank stays blank; legacy plaintext rows decrypt
tolerantly and re-encrypt on next save). Covered fields: `AISettings`
cloudflare token; `NotificationConfig` Slack/Teams webhook URLs; every
`*_key`/`*_secret`/`*_token` on `AmassConfig` + `SubfinderConfig` (Censys IDs /
PassiveTotal usernames stay plaintext — identifiers, not secrets); `ToolCredentials`
(UI-managed BYOK keys — Shodan/HIBP/GitHub/DNS-history, read via `get_credential()`
DB-wins-over-env). Bootstrap secrets `FIELD_ENCRYPTION_KEY`/`SECRET_KEY`/`DB_*`
stay env-only (they bootstrap the crypto + DB). The key comes
from `FIELD_ENCRYPTION_KEY` (a urlsafe-base64 Fernet key) when set, else derived
from `SECRET_KEY`; changing the effective key makes stored secrets unreadable
(re-enter them). Fernet is non-deterministic → these fields can't be used in
equality `.filter()` lookups (only ever read via singleton `.get()` + attribute
access). Tests: `tests/unit/test_crypto.py`.

## AI subsystem — `apps/core/console/ai/` (D-014/D-015)

Core subsystem, deliberately **NOT a registry tool** (no `tool_meta`): it runs
post-finalize over the whole session and has orchestration authority, so its
gate is consent + keys, never workflow membership.

- **Backend:** Cloudflare Workers AI only, called directly via REST. BYOK
  credentials: saved via the /ai page (stored in `AISettings`, write-only —
  never serialized back out, **encrypted at rest** — see Secrets at rest below)
  or `CLOUDFLARE_ACCOUNT_ID`/`CLOUDFLARE_API_TOKEN`
  env vars as fallback (DB wins). `CLOUDFLARE_AI_MODEL` (default
  `@cf/meta/llama-3.3-70b-instruct-fp8-fast`), `CLOUDFLARE_AI_TIMEOUT` (60s),
  `CLOUDFLARE_AI_MAX_CALLS_PER_SCAN` (10 — hard per-scan budget enforced in
  `client.py`).
- **Gate:** `guard.is_ai_active()` = keys configured AND `AISettings.enabled`
  AND current-version consent recorded. Checked at every entry, never cached
  across tasks (revocation is immediate).
- **Pipeline wiring** (all via `apps/core/console/ai/hooks.py`, the fail-graceful
  boundary — the ONLY module pipeline.py imports): `run_ai_post_scan` (triage +
  summaries, inline, after `build_insights` / before `_dispatch_alerts`),
  `maybe_start_agent` (last line of finalize), `maybe_continue_agent` (subscan
  early-return branch — resumes a running agent chain).
- **Orchestration:** one LLM decision per DBOS agent_step workflow (closed action space:
  `run_subscan`/`flag_finding`/`done`); a launched subscan's finalize
  re-enqueues the next step, so nothing blocks the single worker. Bounded by
  `max_agent_iterations` (consumed BEFORE the LLM call) and
  `max_subscans_per_scan`; denial/failure/revocation terminal. Agent subscans
  go only through `create_subscan_session` with `triggered_by="agent"`, and
  `guard.gate_subscan_tools` re-checks `is_passive_tool_set` +
  `DomainAuthorization` at the agent's dispatch boundary (the API-layer gate
  does not cover internal callers).
- **Safety invariants (all tested):** AI-off ⇒ scans byte-identical to pre-AI;
  no active agent subscan without DomainAuthorization; `AIInvocation` audit
  rows are metadata-only (model has no TextField — bodies structurally
  unpersistable); the loop always terminates; no AI failure escapes hooks.py;
  the AI layer never writes `Finding` rows (`test_ai_invariants.py` greps for
  it).

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
GET  /api/dashboard/                      — KPIs, domain status (incl. per-domain exposure_score/grade), urgent findings
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
GET  /api/assets/                         — persistent asset inventory (paginated; ?domain=&kind=&status=&q=), each row with per-severity open-finding counts
GET  /api/assets/summary/                 — inventory totals by kind + active/gone
GET  /api/assets/<id>/                     — asset detail: metadata + extra, findings, scan timeline (seen_in_scans)
GET  /api/insights/                       — trends, top hosts, asset growth, KPIs, Exposure Score + trend (per-scan exposure_score/grade + top-level exposure block)
GET  /api/notifications/config/           — get Slack/Teams notification config
POST /api/notifications/config/           — update notification config
POST /api/notifications/test/             — send a test alert
GET  /api/notifications/alerts/           — alert history
GET  /api/credentials/                    — BYOK key presence booleans + db|env|none source per key (values never returned)
POST /api/credentials/                    — set/clear BYOK keys (write-only; None=unchanged, ""=clear→env fallback)
GET  /api/ai/config/                      — AI settings (credential presence booleans only — values are never returned)
POST /api/ai/config/                      — enable/disable + save credentials (write-only; None=unchanged, ""=clear→env fallback); enabling requires current-version consent (consent_accepted stamps it)
POST /api/ai/test/                        — Workers AI connectivity probe (fixed prompt, no scan data; allowed pre-consent)
GET  /api/ai/triage/<uuid>/               — triage status + ranked items + agent decisions (disabled|absent|running|complete|failed)
POST /api/ai/triage/<uuid>/run/           — manual (re-)run via DBOS (409 while scan/triage in flight)
GET  /api/ai/audit/                       — paginated AI call log (metadata only, never bodies)
```

### Other routes
- `/reports/<uuid>/csv/` → CSV export (**synchronous** Django view on the web tier, `_report_auth_required` — accepts session auth or `?token=<access_token>`)
- `/reports/<uuid>/pdf/` → PDF export (**synchronous** Django view on the web tier, rendered with WeasyPrint, `_report_auth_required` — accepts session auth or `?token=<access_token>`)
- **Reports UI:** the React SPA has a dedicated **Reports page** (`/reports`, nav item + `ReportsPage.jsx`) listing completed scans with per-scan CSV/PDF export + a `min_severity` filter (auth'd fetch+Blob, JWT in header); also still available as CSV/PDF buttons on the Scan Detail page. The SPA `/reports` route and the Django `/reports/<uuid>/{csv,pdf}/` endpoints coexist — Django's SPA catch-all serves bare `/reports`, and the Vite dev proxy uses a `^/reports/.+` regex so only the endpoints proxy to Django.
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
| `tests/unit/test_domain_security.py` | 46 | Passive DNS/DNSSEC/email-auth/RDAP — **slow, real network** (active AXFR/open-relay/MTA-STS tests moved to test_domain_probe) |
| `tests/unit/test_domain_probe.py` | 17 | Active domain probes — tool_meta (active/runner/group), AXFR zone transfer, MTA-STS policy fetch, SMTP open-relay (all mocked, source="domain_probe"), orchestrator stamps controls |
| `tests/unit/test_domains.py` | 13 | Domain CRUD |
| `tests/unit/test_historical_urls.py` | 37 | collector (missing binary, timeout, happy path), analyzer (noise filter, FK links, dedup), scanner |
| `tests/unit/test_httpx.py` | 16 | JSON parser, Port lookup, Subdomain link, honest UA, tech-detect flag + technology storage/dedup |
| `tests/unit/test_github_recon.py` | 39 | Org resolution (domain-derived + `GITHUB_ORG` override), collector (org/user confirm + fallback, repo enumeration/pagination, fork skip, `GITHUB_MAX_REPOS`/`GITHUB_MAX_REQUESTS` caps, config-file base64 decode + size cap, BYO-token auth header + honest UA), fail-graceful (timeout/500/rate-limit-backoff/hard-403/bad-JSON never raise), infra-reference extraction (hostname/api-endpoint/cloud-bucket, apex excluded), analyzer (summary + per-ref low Findings, dedup), scanner never-raises |
| `tests/unit/test_hudson_rock.py` | 17 | collector (both endpoints keyless + honest UA, fail-graceful on timeout/500/429/bad-JSON, 429 retry), analyzer (severity, counts/families/URLs/attribution, no-finding-when-zero, **no plaintext/email persisted**, URL cap), scanner |
| `tests/unit/test_dns_history.py` | 17 | Historical-DNS passive tool — collector (no-URL no-op, fail-graceful on request-error/non-200/bad-JSON, honest UA, type filter, dedup, cap, wrapped-dict), analyzer (info Finding per record, skip empty), scanner (no-domain/no-records skip, saves, never-raises) |
| `tests/unit/test_breach_check.py` | 29 | Two-tier BYOK — free XposedOrNot parse (keyless + honest UA) + HIBP `breacheddomain` path (key set → HIBP used, `hibp-api-key` header sent, 404/403 = no-data), fail-graceful (timeout/500/429/bad-JSON never raise), 429 backoff, analyzer (severity high on large-account/recent, counts + attribution, no-finding-when-zero, breach-name cap), **PRIVACY: alias keys/emails/credentials never persisted (collector + analyzer + end-to-end)**, scanner |
| `tests/unit/test_shodan.py` | 20 | collector tier selection (free InternetDB vs paid host API, BYO-key), `SHODAN_MAX_IPS` cap on paid path only, fail-graceful (404/timeout/500/429/bad-JSON never raise), analyzer (exposure + CVE findings, `extra["cve_ids"]` for cve_intel enrichment, invalid-CVE filter), scanner |
| `tests/unit/test_js_secrets.py` | 26 | `.js` URL filter + cap, fetch-error handling, gitleaks JSON parser, analyzer Findings + dedup + secret redaction (full secret never stored), scanner, binary-missing/timeout |
| `tests/unit/test_github_secrets.py` | 32 | no-token skip (BYOK gate), org resolution (override high-confidence / apex-label low-confidence), org-scoped query building + global-search opt-in, rate-limit helpers (429/403-zero-remaining/secondary + capped backoff), collector fail-graceful (network/500/429-exhausted/bad-JSON never raise) + 429-then-success backoff, search→fetch→gitleaks happy path, gitleaks binary-missing/timeout raise, redaction (full secret never persisted — asserted at DB level), analyzer Finding shape + dedup, scanner |
| `tests/unit/test_k8s_manifests.py` | 66 | k8s manifest structure — split web/worker Deployments, tier labels, Service→web-only selector, envFrom order, probes + probe-host, worker NET_RAW/role/entrypoint, no-PVC, kustomization |
| `tests/unit/test_katana.py` | 19 | JSONL parser, Port/Subdomain FK links, scanner orchestrator, honest UA |
| `tests/unit/test_management_commands.py` | 11 | `verify_tools` + other management commands |
| `tests/unit/test_render_pipeline_diagram.py` | 12 | `render_pipeline_diagram` — build_structure covers every registry tool (drift guard), counts consistent, groups min-phase ordered, active flags match registry, html/text/json renderers + `-o` file write |
| `tests/unit/test_monitoring.py` | 17 | sync_domain_monitoring_jobs, per-domain monitoring, authorization gate |
| `tests/unit/test_naabu.py` | 10 | JSON parser, FK to IPAddress |
| `tests/unit/test_nmap.py` | 26 |
| `tests/unit/test_nmap_backports.py` | 16 | Backport-aware CVE demotion engine — Debian/Ubuntu version compare, check_backport, `protocol 2.0` false-positive guard | Severity mapping, vulners XML parser, web/non-web exclusion, backport matching |
| `tests/unit/test_notifications.py` | 41 | NotificationConfig, Slack/Teams alerts, alert-history API, AI summary block/fact (absent = payload byte-identical), alert idempotency on finalize replay (skip when already sent, retry when only failed), "N new since last scan" line/fact (counts only alerted new findings, absent = byte-identical) |
| `tests/unit/test_nuclei.py` | 33 | CVE parsing, severity, dedup, URL linking, collector, honest UA |
| `tests/unit/test_nuclei_network.py` | 28 | Network-template parsing, non-web targeting, collector |
| `tests/unit/test_pipeline_phases.py` | 1 | Phase ordering sanity |
| `tests/unit/test_qcluster_config.py` | 3 | Scan-timeout invariants (Q_CLUSTER removed; SCAN_TASK_TIMEOUT + watchdog bound) |
| `tests/unit/test_durable_task.py` | 7 | `@durable_task` engine adapter (H6) — in-process call, `.delay()` enqueue, dedupe template + override, registry, real tasks are DurableTasks, enqueue_* wrappers delegate |
| `tests/unit/test_credentials.py` | 13 | UI-managed BYOK credentials (C1+C3) — singleton, ciphertext-at-rest/plaintext-via-ORM, resolver DB-wins-over-env + env fallback + source + never-raises, write-only API (presence-only never values, set/none-unchanged/clear), and a DB key reaching `shodan.collect` (paid tier, no env key) |
| `tests/unit/test_reports.py` | 80 | CSV export content/structure, PDF export (WeasyPrint, mocked via _render_pdf), min_severity filter, per-severity count aggregation, issue grouping, scope/CWE/CVSS/risk enrichment, WAF coverage block, technology stack block, AI Analyst Summary block (absent without AI rows), "Since Your Last Scan" delta block (new/resolved/still-open, baseline + subscan + min_severity rules, CSV new-flag column), per-finding "Recommended Next Steps" checklist (hosted-only gating, effective-key mapping incl. email control, empty for unmapped) |
| `tests/unit/test_waf_detection.py` | 16 | WAF/block/challenge classifier (spec C1) — vendor fingerprint, false-positive guards, analyzer wiring |
| `tests/unit/test_coverage.py` | 6 | Scan coverage (spec C2) — endpoint counts, dominant vendor, report note wording |
| `tests/unit/test_scans.py` | 30 | ScanSession, scheduling, scan_start views |
| `tests/unit/test_scheduler.py` | 33 | reap_stuck_scans, token purge, daily_scan, authorization gate, `SCHEDULED_SCANS_ENABLED` switch |
| `tests/unit/test_service_detection.py` | 64 | XML parsing, Port enrichment, is_web |
| `tests/unit/test_ssh_checker.py` | 34 | SSH probe, host key, kex/cipher/MAC, auth, collector |
| `tests/unit/test_subfinder.py` | 10 | JSON parser, dedup, hostname normalization |
| `tests/unit/test_subscan.py` | 12 | Targeted re-scan of a single tool / subset |
| `tests/unit/test_typosquat.py` | 36 | candidate generation (all 8 techniques, uniqueness, no-original, www-strip, cap/truncation-logged), passive DNS registration check (A/MX/NS, NXDOMAIN + timeout never raise), weaponization homepage probe (login form + brand mention flagged, fetch failure graceful), analyzer severity (A/MX → medium, NS-only → low, login-form/brand → high), scanner (saves + never-raises), concurrent collect (order-preserving, all-registered-checked, fetch cap) |
| `tests/unit/test_takeover_check.py` | 35 | collector (missing binary, bad JSON, happy path), analyzer (vulnerable/non-vulnerable, FK link, dedup), scanner |
| `tests/unit/test_tls_checker.py` | 87 | Cert parsing, ciphers, protocols, HSTS, collector, scanner, cipher enumeration |
| `tests/unit/test_tools_healthcheck.py` | 14 | Tool binary preflight / health checks |
| `tests/unit/test_user_profile.py` | 7 | UserProfile `must_change_password` flag |
| `tests/unit/test_settings_security.py` | 16 | SECRET_KEY strength guard (DEBUG=False + insecure default) |
| `tests/unit/test_insights_builder.py` | 4 | FindingTypeSummary prune only when aggregation_complete |
| `tests/unit/test_exposure_score.py` | 38 | Exposure Score — formula (clean=0, weights, saturation cap), grade bands, trend delta (up/down/flat/no-baseline), builder populates ScanSummary, insights + dashboard API fields, PDF report exposure block |
| `tests/unit/test_web_checker.py` | 58 | Headers, cookies, CORS, disclosure, collector; security.txt (RFC 9116) — expires parsing, SPA-catch-all guard, missing=info/expired=low findings, reachable-vs-absent (unreachable ⇒ no false "missing"), apex-only collection + fail-graceful |
| `tests/unit/test_passive_scan.py` | 27 | registry `active` classification (domain_security passive / domain_probe active), `is_passive_tool_set`, Data Leak grouping, Passive Scan workflow all-passive invariant, passive-scan auth-gate bypass + active-scan gate, subscan gate |
| `tests/unit/test_workflow_runner.py` | 35 | run_workflow, naabu-gated service_detection injection, step failure, cancellation, phase parallelism (concurrent same-phase; LOW_MEMORY serialises heavy phases but light phase-1 tools still parallel) |
| `tests/unit/test_default_workflow.py` | 5 | Full Scan is the default workflow with the complete 18-tool set (migration 0021), idempotent gap-fill |
| `tests/integration/test_scan_flow.py` | 12 | Full pipeline (mocked) + delete cascade |
| `tests/unit/test_update_check.py` | 22 | Update-available check — version parse/compare, cached GitHub fetch, fail-graceful on timeout/HTTP-error/bad-payload, endpoint shape |
| `tests/unit/test_proc_env.py` | 4 | `go_memory_env()` — GOMEMLIMIT/GOGC set in low profile, unchanged otherwise, preserves existing env |
| `tests/unit/test_coverage_regression.py` | 10 | Silent-block coverage counting (probed-vs-reached), coverage-regression finding (high block ratio / findings drop / stable = no flag), partial scan status when a tool fails |
| `tests/unit/test_ai_client.py` | 20 | Workers AI client — envelope parsing (dict/string response), audit rows + token accounting, 429/5xx retry, schema-mismatch corrective retry, per-scan call budget |
| `tests/unit/test_ai_models.py` | 9 | AISettings singleton + consent versioning, AIInvocation no-TextField invariant, audit survives session deletion, OneToOne/unique constraints |
| `tests/unit/test_ai_guard.py` | 12 | is_ai_active gate matrix, gate_subscan_tools (unknown-drop, passive-allowed, active-needs-DomainAuthorization) |
| `tests/unit/test_ai_api.py` | 27 | config GET/POST (no credential leak, CONSENT_REQUIRED, consent stamping, disable-keeps-consent), test endpoint, triage GET/run status matrix, triage task, audit pagination |
| `tests/unit/test_ai_context.py` | 7 | Prompt builders — severity-ranked selection + cap, info excluded, description truncation, message payloads |
| `tests/unit/test_ai_triage.py` | 6 | Ranked item persistence, hallucinated/duplicate id drop, failed status, replace-on-rerun |
| `tests/unit/test_ai_summaries.py` | 7 | Report + alert kinds, absent-on-failure, triage overview feeds prompt, update-in-place |
| `tests/unit/test_ai_pipeline.py` | 10 | Invariants 1 + 5 — AI-off finalize byte-identical, hook ordering before alerts, subscan skip, failure swallowing |
| `tests/unit/test_ai_orchestrator.py` | 22 | Agent loop — gate/revocation terminal, iteration pre-consumption, caps, denied-without-auth, sanctioned subscan path (`triggered_by="agent"`), flag never mutates Finding.status, chain hooks |
| `tests/unit/test_ai_invariants.py` | 3 | Grep-style: AI layer only Finding.objects.filter, audit writer has no body params, client creates only AIInvocation |
| `tests/integration/test_ai_flow.py` | 6 | AI end-to-end (only the Cloudflare HTTP edge + queue mocked): finalize → triage/summaries/agent/audit, report + alert carry output, subscan chain roundtrip, AI-off zero traces, Cloudflare-down scan still completes; plus an opt-in LIVE smoke test (runs only with real `CLOUDFLARE_*` env: `pytest tests/integration/test_ai_flow.py -k live`) |
| `tests/test_api_endpoints.py` | 104 | Smoke tests for all API endpoints (auth + payload shape), incl. build-provenance `/health/` + `/api/version/` (+ `no-store`) + update-check `/api/version/latest/` |
| `tests/unit/test_crypto.py` | 16 | At-rest secret encryption — Fernet roundtrip/non-determinism/legacy-plaintext tolerance, key derivation/override/rotation, DB-holds-ciphertext + ORM-returns-plaintext for AI/notifications/amass/subfinder |
| `tests/unit/test_login_ratelimit.py` | 13 | Login brute-force limiter — threshold lockout, window reset, success clears, X-Forwarded-For keying (+ untrusted-XFF fallback / spoof-evasion), middleware integration (per-IP isolation, disabled bypass, refresh endpoint unaffected) |

| `tests/unit/test_asset_inventory.py` | 11 | Asset-inventory rollup — upsert per kind, dedup across scans, honest gone-marking (completed-only, observed-kinds-only, not on partial/subscan), no-Domain skip, Finding→Asset linkage (url/port/target) |
| `tests/unit/test_asset_inventory_api.py` | 14 | `/api/assets/` — auth required, list (filters kind/status/domain/q, pagination, per-asset open-finding counts), summary (totals + by_kind), detail (metadata/findings/seen_in_scans, 404); Finding→Asset cross-link in the findings API; dashboard asset KPI |

**Total: 1842 tests** (1796 fast + 46 slow domain_security)

Frontend: **22 Vitest + Testing Library tests** (`frontend/src/**/*.test.{js,jsx}`, happy-dom env) — auth token helpers, the `Badge` component, the axios 401-refresh interceptor, the Assets `SeverityChips`, and the Credentials source-label mapping. Run with `cd frontend && npm run test:run`.
