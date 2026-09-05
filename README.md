<p align="center">
  <a href="https://cybersecify.com"><img src="docs/brand/cybersecify-horizontal.svg" alt="Cybersecify" height="72"></a>
</p>

# OpenEASD

[![GitHub Stars](https://img.shields.io/github/stars/cybersecify/OpenEASD?style=social)](https://github.com/cybersecify/OpenEASD/stargazers)
[![CI](https://github.com/cybersecify/OpenEASD/actions/workflows/ci.yml/badge.svg)](https://github.com/cybersecify/OpenEASD/actions/workflows/ci.yml)
[![CodeQL](https://github.com/cybersecify/OpenEASD/actions/workflows/codeql.yml/badge.svg)](https://github.com/cybersecify/OpenEASD/actions/workflows/codeql.yml)
[![Docker Image](https://img.shields.io/badge/ghcr.io%2Fcybersecify%2Fopeneasd-latest-2496ed?logo=docker&logoColor=white)](https://github.com/cybersecify/OpenEASD/pkgs/container/openeasd)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**See what attackers see. Use it before they do.**

Use it as a **red teamer** to map external surface fast on targets you're authorised to test. Use it as a **defender** to see what's leaking out of your own infrastructure: subdomains, exposed ports, dangling CNAMEs, missing TLS, known CVEs, without paying $500-5000/mo for a commercial EASM platform.

OpenEASD wraps the open-source recon tools security teams already use: `subfinder`, `amass`, `alterx`, `dnsx`, `subzy`, `cloud_enum`, `naabu`, `nmap`, `httpx`, `gau`, `katana`, `nuclei`, `gitleaks`, behind a single web UI with scheduling, alerts, and findings tracking. Twenty-seven tools across DNS/DNSSEC, email (SPF/DMARC/DKIM/MTA-STS/open-relay), TLS, SSH, ports, CVEs, subdomain takeover, ASN/IP-range discovery, historical URLs, cloud assets, exposed secrets in JavaScript, leaked secrets in public GitHub (passive; searches GitHub's code-search API for the org's committed credentials and runs gitleaks over the hits — bring-your-own GitHub token), public-source infrastructure exposure (passive; internal hostnames, cloud buckets, and API endpoints leaked in the org's public GitHub repos), infostealer-log exposure (via Hudson Rock's keyless Cavalier API), data-breach exposure (passive; free XposedOrNot tier out of the box, authoritative with a bring-your-own Have I Been Pwned key), Shodan-sourced exposure (passive; free InternetDB tier out of the box, richer with a bring-your-own Shodan key), lookalike / typosquat domain detection (passive; phishing infrastructure and brand abuse targeting your domain), technology fingerprinting, web hygiene, and CVE prioritisation (EPSS + CISA KEV). Run a **passive scan** (public-source only, no authorization needed) or an **active scan** (probes the target, authorization required). Self-hosted, MIT-licensed, one `docker run`. Results stay on your machine — unless you enable the optional Cloudflare Workers AI analysis (off by default, explicit consent required), which sends finding data to your own Cloudflare account.

Optionally, OpenEASD can rank each scan's findings by exploitability and explain why (a "fix these first" list with per-finding rationale), schedule targeted follow-up scan steps based on what was found, and write plain-language report and alert summaries — using Cloudflare Workers AI with your own account (credentials entered on the AI Analysis page, or via `CLOUDFLARE_ACCOUNT_ID` + `CLOUDFLARE_API_TOKEN` env vars). Off by default; enabling it requires explicit consent in the UI, every call is audit-logged (never the prompt or response contents), and active follow-up scanning still requires the same domain authorization as manual scans.

Built by [Rathnakara G N](https://www.linkedin.com/in/rathnakaragn/) and [Ashok S Kamat](https://www.linkedin.com/in/ashokskamat/) of [Cybersecify](https://cybersecify.com), the same tool we run in engagements and on our own infrastructure.

## Who this is for

- **In-house security engineers and IT-doing-security teams** at small-to-mid orgs scanning their own external surface
- **Small security consultancies** monitoring a handful of clients
- **Bug bounty hunters** who want a unified view of recon output across programs they're authorised to test
- **Solo self-hosters and security learners** auditing their own infra

## Who this isn't for

- **Enterprise SOCs**: no RBAC, SAML, multi-tenant, or Postgres (yet)
- **Anyone needing to scan domains they don't own or aren't authorised to test**: OpenEASD is intentionally not a "scan-anyone" hosted service. Running it implies you own or have written authorisation for your targets

## Supply chain transparency

OpenEASD is a security tool, so it's reasonable to ask whether the tool
itself is trustworthy. Here's what we do (and don't do) to make that
auditable.

### What's in the Docker image

Every external tool we ship is downloaded inside the Docker build from
its maintainer's official source. No repackaging, no mirroring:

| Tool | Upstream source |
|---|---|
| `subfinder`, `dnsx`, `naabu`, `httpx`, `nuclei`, `alterx`, `katana` | [github.com/projectdiscovery](https://github.com/projectdiscovery) (signed releases) |
| `amass` | [github.com/owasp-amass/amass](https://github.com/owasp-amass/amass) (OWASP) |
| `subzy` | [github.com/PentestPad/subzy](https://github.com/PentestPad/subzy) (Go modules) |
| `gau` | [github.com/lc/gau](https://github.com/lc/gau) (Go modules) |
| `cloud_enum` | [github.com/initstring/cloud_enum](https://github.com/initstring/cloud_enum) |
| `gitleaks` | [github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) (MIT, signed releases) |
| `nmap` | `apt-get install nmap` (Ubuntu 24.04 official) |

Verbatim install commands are in the [Dockerfile](Dockerfile); every
version is pinned. To verify a binary, pull the same version directly
from the upstream URL; it should byte-match what ships in the image.

### How the image is built

Every push to `main` and every `vX.Y` tag triggers
[`.github/workflows/ci.yml`](.github/workflows/ci.yml), which builds
`linux/amd64` images and publishes to
`ghcr.io/cybersecify/openeasd`. The build is reproducible from the
public source; the published image carries:

- **SBOM** (Software Bill of Materials, SPDX format): every package in
  the image, retrievable via `docker buildx imagetools inspect`
- **SLSA provenance attestation**: cryptographic proof that the image
  was built by this repo's GitHub Actions, not swapped or rebuilt
  elsewhere

```bash
# Both images carry their own SBOM + provenance; inspect either target:
docker buildx imagetools inspect ghcr.io/cybersecify/openeasd-web:v2.0.0    --format '{{ json .SBOM }}'
docker buildx imagetools inspect ghcr.io/cybersecify/openeasd-worker:v2.0.0 --format '{{ json .Provenance }}'
```

### What we don't do

- **No telemetry.** OpenEASD doesn't phone home, doesn't check for
  updates, doesn't send your scan results anywhere.
- **No auto-update.** The version you pulled is the version that runs.
- **No external callbacks during scans**: the only network traffic is
  the scan itself, originating from the tools shipped in the image.

Block all egress at your firewall (except what's needed to reach scan
targets) and OpenEASD continues to work.

### Continuous security checks

| Check | Tool | Runs on |
|---|---|---|
| Python SAST | `bandit` | Every push + PR |
| Python CVE scan | `pip-audit` | Every push + PR |
| Semantic security analysis | CodeQL (Python + JS/TS) | Every push + PR + weekly |

GitHub Actions are pinned to commit SHAs (not floating tags) so a
compromised action update can't silently rotate into the build.
Dependabot keeps them current on a weekly cadence.

Open security alerts are public on the
[Security tab](../../security); we don't hide gaps.

### Want to verify? Build from source.

If you don't trust the published Docker image, build it yourself;
every step is in the [Dockerfile](Dockerfile):

```bash
git clone https://github.com/cybersecify/OpenEASD
cd OpenEASD
docker build -t openeasd .
```

### Known gap (named honestly)

- **Docker images are not yet cosign-signed.** SBOM + SLSA provenance
  in the manifest covers the "what's in it + who built it" question;
  cosign would add a separate, externally-verifiable signature. On the
  roadmap.

For vulnerability reporting, see [SECURITY.md](SECURITY.md).

## System requirements

The scan tools (nuclei and amass especially) are memory-hungry. On a host with
too little RAM the kernel will OOM-kill them mid-scan, so scans finish partial or
empty.

| | RAM | vCPU | Disk |
|---|---|---|---|
| **Minimum** | 2 GB | 1 | 5 GB |
| **Recommended** | 4 GB | 2 | 10 GB |
| **1 GB host** | set `OPENEASD_LOW_MEMORY=true` | 1 | 5 GB |

OpenEASD **adapts to the host automatically** via `OPENEASD_PROFILE` (default
`auto`, detected from RAM):

| Profile | When | Behaviour |
|---|---|---|
| `low` | < 2 GB (or `OPENEASD_LOW_MEMORY=true`) | tools run sequentially, nuclei throttled, amass skips brute — completes on ~1 GB without OOM |
| `balanced` | 2–8 GB | phase-parallel, nuclei `-c 25` |
| `high` | ≥ 8 GB | phase-parallel + higher local concurrency and deeper enumeration |

Set `-e OPENEASD_PROFILE=low|balanced|high` to override auto-detection. On a 1 GB
box, auto-detect picks `low` (or set it explicitly); a few GB of swap also helps.

**On politeness:** a bigger box scales *local* parallelism, not how hard the
target is hit — the per-target request rate stays capped across all profiles, so
`high` doesn't flood targets or trip their WAFs (which the report flags anyway).

## Quick start

OpenEASD runs as three services (PostgreSQL + web + worker). Set the secrets in
`docker-compose.yml` (`SECRET_KEY`, `DB_PASSWORD`, `ALLOWED_HOSTS`), then:

```bash
docker compose up -d --build
```

Open http://localhost:8000 → log in with `admin` / `admin` (you'll be forced to set a new password) → add a domain → run a scan. Full env-var reference, update path, Kubernetes manifests, and standalone (no-Docker) install are under [Deployment](#deployment).

## Features

- **Automated pipeline**: 27-tool scan workflow from domain to findings
- **Network attack surface scanning**: CVEs, TLS/cert issues, SSH config, network protocol vulnerabilities
- **CVE prioritisation**: EPSS exploit-probability scores + CISA KEV (known-exploited-in-the-wild) flags enrich CVE findings in place, so you triage by real-world risk rather than severity alone
- **Dynamic workflows**: Create custom scan configurations, enable/disable tools per workflow
- **Tool auto-registration**: Add new tools with zero core modification
- **Live scan progress**: Real-time pipeline status with per-tool step tracking
- **Scan stop/cancel**: Graceful cancellation between tool steps
- **Unified findings**: All tools write to a single Finding model with lifecycle tracking
- **Continuous monitoring**: Per-domain rescans on a configurable schedule (6h / 12h / 24h / 48h / weekly)
- **Subscan**: Re-run specific tools on existing scan assets without full rediscovery
- **Reports**: CSV and PDF export
- **Alerts**: Slack and Teams webhooks with configurable severity threshold; test button and alert history in the UI
- **Scheduling**: One-time, recurring, and daily automated scans
- **Domain authorization enforcement**: Each domain requires a recorded authorization (owner / written consent / bug bounty) before scans can start. Managed in Django admin; React blocks the Scan button and the API enforces it server-side
- **JWT auth**: Stateless Bearer token authentication with refresh token rotation
- **Forced password change**: Default `admin/admin` password must be changed on first login

## Scan Pipeline

```
── Domain Intelligence ──────────────────────────────────────────────────────
Phase 1  Domain Security   - DNS, DNSSEC chain-of-trust, email
                             (SPF/DMARC/DKIM/MTA-STS/open-relay), RDAP checks
Phase 1  Hudson Rock        - Infostealer-log exposure via Hudson Rock's keyless
                             Cavalier API (aggregate counts only, no plaintext)
Phase 1  GitHub Secrets      - Leaked secrets in public GitHub via gitleaks
                             (passive; BYO GITHUB_TOKEN, redacted before storage)
Phase 1  Typosquat          - Lookalike / typosquat domain detection (passive;
                             registered lookalikes via public DNS — phishing/brand abuse)
Phase 1  Breach Check       - Data-breach exposure via XposedOrNot (free/keyless)
                             or Have I Been Pwned (BYO key); counts only, no PII

── Surface Enumeration ─────────────────────────────────────────────────────
Phase 2  Subfinder         - Passive subdomain enumeration
Phase 2  Amass             - Active subdomain enumeration
Phase 2  Alterx            - Subdomain permutation from discovered subdomains
Phase 2  ASN Discovery     - Owned ASN/CIDR ranges via amass intel (reports only)
Phase 2  GitHub Org Recon  - Infra refs (internal hostnames, cloud buckets, API
                             endpoints) leaked in the org's public GitHub repos
                             (passive; official API — keyless, richer with a token)
Phase 3  DNSx              - DNS resolution, public IP filtering
Phase 4  Takeover Check    - Subdomain takeover detection via subzy
Phase 4  Cloud Assets      - Public S3/Azure/GCP bucket enumeration (cloud_enum)

── Port Discovery ───────────────────────────────────────────────────────────
Phase 5  Naabu             - TCP port scanning (top 100; CDN edge IPs excluded)
Phase 6  Service Detection - Classify ports as web/non-web via nmap -sV (auto)

── Network Exposure ─────────────────────────────────────────────────────────
Phase 7  Nmap              - CVE scanning via NSE vulners (non-web ports)
Phase 7  TLS Checker       - Certificate, cipher, and protocol analysis
Phase 7  SSH Checker       - SSH configuration audit
Phase 7  Nuclei Network    - Network protocol vuln templates (non-web ports)

── Web Exposure ─────────────────────────────────────────────────────────────
Phase 8  httpx             - Web probing, URL discovery, technology fingerprinting
Phase 9  Historical URLs   - Archived URL discovery via gau
Phase 10 Katana            - Deep URL crawl on top of httpx
Phase 11 Nuclei            - Web vulnerability scanning (community templates)
Phase 11 Web Checker       - Security headers, cookies, CORS analysis
Phase 11 JS Secrets        - Hardcoded secrets in JavaScript via gitleaks

── Prioritization ───────────────────────────────────────────────────────────
Phase 12 CVE Intel         - Enrich CVE findings with EPSS + CISA KEV

── AI analysis (optional; off by default, bring-your-own Cloudflare) ──────────
Post-scan Triage          - Rank findings by exploitability (CISA KEV + EPSS
                            outrank raw CVSS) with a per-finding rationale, plus
                            plain-language report and alert summaries
Post-scan Orchestration   - A bounded agent may schedule targeted follow-up
                            subscans based on what was found (still gated by the
                            same domain authorization as manual scans)
```

Every scan probe also carries an honest `OpenEASD/1.0` user agent (so a target
can allowlist it), and the report flags WAF/edge blocking so an empty result
means "clean", never "silently blocked".

The AI stage runs only when Cloudflare Workers AI credentials are provided
(saved on the AI Analysis page, or `CLOUDFLARE_ACCOUNT_ID` / `CLOUDFLARE_API_TOKEN`
env vars) **and** an operator enables it with explicit consent. With it off — the
default — the pipeline ends at Phase 12 and nothing leaves your machine. Every AI
call is recorded in an audit log (time, scan, purpose, model, token counts,
finding IDs); prompt and response contents are never stored.

## Architecture

```
apps/core/              - Infrastructure (never changes)
  api/                  - Django Ninja API, JWT auth, error handlers
  api/tokens/           - BlacklistedToken model (JWT JTI blacklist)
  assets/               - Network assets: Subdomain, IPAddress, Port
  web_assets/           - Web assets: URL
  service_detection/    - Classifies ports as web/non-web (core, always runs)
  findings/             - Unified Finding model
  scans/                - ScanSession, pipeline orchestrator
  workflows/            - Dynamic workflow engine + tool registry
  scheduler/            - Scan callables (daily / monitoring sweep / user-schedule sweep / watchdog) driven by DBOS @scheduled workflows
  durable/              - DBOS engine, scan/AI workflows, dbos_worker command
  notifications/        - Slack/Teams alerts
  insights/             - Scan summaries, charts
  reports/              - CSV/PDF export
  ai/                   - AI analysis (Cloudflare Workers AI, BYOK): triage, orchestration, summaries, consent + audit
  domains/              - Domain management
  dashboard/            - UI home

apps/                   - Tool apps (add/remove freely)
  domain_security/      - DNS, email, RDAP checks
  hudson_rock/          - Infostealer-log exposure (Hudson Rock Cavalier API)
  github_secrets/       - Leaked secrets in public GitHub (gitleaks, BYO token)
  breach_check/         - Data-breach exposure (XposedOrNot free / HIBP BYO key)
  subfinder/            - Passive subdomain enumeration
  amass/                - Active subdomain enumeration
  alterx/               - Subdomain permutation (from discovered subdomains)
  dnsx/                 - DNS resolution
  takeover_check/       - Subdomain takeover detection (subzy)
  naabu/                - Port scanning
  nmap/                 - CVE scanning (NSE vulners)
  tls_checker/          - TLS/cert/cipher analysis
  ssh_checker/          - SSH configuration audit
  nuclei_network/       - Network protocol vuln scanning
  httpx/                - Web probing
  historical_urls/      - Archived URL discovery (gau)
  katana/               - Deep URL crawl
  nuclei/               - Web vulnerability scanning
  web_checker/          - Security headers, cookies, CORS

frontend/               - React 19 + Vite 8 SPA
  src/pages/            - Page components
  src/components/       - Shared UI primitives (Badge, Spinner, Pagination, ConfirmButton)
  src/components/ui/    - shadcn/ui primitives (Button, Card, Table, AlertDialog, …)
  src/hooks/            - useFetch, usePolling
  src/api/client.js     - JWT apiFetch wrapper
  src/auth.js           - localStorage token helpers
```

## Deployment

### Docker Compose (recommended)

OpenEASD runs as three services — **PostgreSQL + web + worker**. Edit the
secrets in `docker-compose.yml` (`SECRET_KEY`, `DB_PASSWORD`, `ALLOWED_HOSTS`),
then:

```bash
docker compose up -d --build
```

- `db` — PostgreSQL 17 (app data + the DBOS durable-execution schema)
- `web` — the slim `openeasd-web` image (UI/API + PDF reports; no scanner tools)
- `worker` — the `openeasd-worker` image (DBOS worker + the full scanner matrix, `NET_RAW`)

Open http://localhost:8000, then log in with `admin` / `admin`. You will be forced to set a new password before accessing the app.

> **Production note:** `ALLOWED_HOSTS="*"` is fine for evaluation on a private network. For internet-facing deployments, narrow it to your actual hostname or IP (e.g. `ALLOWED_HOSTS="scanner.example.com,127.0.0.1"`) and set `CSRF_TRUSTED_ORIGINS` if accessing over a domain.

#### Update to latest

```bash
docker compose pull        # pulls fresh openeasd-web + openeasd-worker
docker compose up -d       # recreates changed containers; the db volume persists all data
```

#### Environment variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | insecure default | Django secret key; **set this in production** |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated hostnames (add your server IP/domain) |
| `CSRF_TRUSTED_ORIGINS` | *(none)* | Required if accessing via a domain, e.g. `https://openeasd.example.com` |
| `DEBUG` | `False` | Set `True` only for local development |
| `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | `db` / `5432` / `openeasd` / `openeasd` / — | PostgreSQL connection (or set `DATABASE_URL`) |
| `DBOS_SCAN_CONCURRENCY` | `2` | Max scans executing at once (Postgres has no single-writer lock) |
| `CLOUDFLARE_ACCOUNT_ID` / `CLOUDFLARE_API_TOKEN` | *(none)* | Optional AI analysis (or enter on the AI Analysis page) |
| `SLACK_WEBHOOK_URL` | *(none)* | Slack incoming webhook for scan alerts (can also be set in the Notifications UI) |
| `MS_TEAMS_WEBHOOK_URL` | *(none)* | Teams incoming webhook for scan alerts (can also be set in the Notifications UI) |
| `ALERT_SEVERITY_THRESHOLD` | `high` | Minimum severity to trigger alerts; overridden by the Notifications UI setting |
| `SCAN_DAILY_HOUR` | `2` | Hour for daily scheduled scans (24h, UTC) |
| `SCAN_DAILY_MINUTE` | `0` | Minute for daily scheduled scans |
| `REPORT_CTA_URL` | *(none)* | Optional URL appended to PDF and CSV reports. Renders only when both `REPORT_CTA_URL` and `REPORT_CTA_TEXT` are set |
| `REPORT_CTA_TEXT` | *(none)* | Optional call-to-action line shown alongside `REPORT_CTA_URL` in PDF/CSV reports |

### Kubernetes

Manifests are in `k8s/`. Requires a cluster with an nginx Ingress controller.

**1. Set your secret**

Edit `k8s/secret.yaml` and replace `REPLACE_WITH_OPENSSL_RAND_HEX_32` with a real key:

```bash
openssl rand -hex 32
```

**2. Set your domain**

Edit `k8s/configmap.yaml` (`ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`) and `k8s/ingress.yaml` (`host`) to match your domain.

**3. Deploy**

```bash
kubectl apply -k k8s/
```

**4. Update to latest image**

```bash
kubectl rollout restart deployment/openeasd-web deployment/openeasd-worker -n default
```

#### Architecture

Single pod, two containers, one `ReadWriteOnce` PVC:

| Container | Command | Resources |
|---|---|---|
| `web` | `gunicorn` (2 workers) | 256Mi–512Mi |
| `worker` | `manage.py dbos_worker` | 512Mi–4Gi, `NET_RAW` capability |

An init container runs migrations and admin user setup before the main containers start. The `worker` container gets `NET_RAW` capability for nmap/naabu port scanning.

> **Scaling:** the app Deployment is `replicas: 1` (one web + one worker container) alongside a PostgreSQL StatefulSet (`k8s/postgres.yaml`). Postgres removes the old single-writer limit, so the worker can be split into its own Deployment and scaled to multiple replicas pulling the same DBOS queue.

#### Health check

`GET /health/` returns `{"status": "ok"}`, used by K8s readiness and liveness probes (no auth required).

### Standalone (no Docker)

The fastest way to get running on a Linux server or macOS without Docker:

```bash
git clone https://github.com/cybersecify/OpenEASD.git
cd OpenEASD

# Linux (installs all deps + systemd services)
sudo ./install.sh

# macOS
./install.sh

# Skip amass if you don't need active subdomain enumeration (saves ~10 min)
sudo ./install.sh --skip-amass
```

The script installs: Python/uv, Node.js, nmap, ProjectDiscovery tools (subfinder, dnsx, naabu, httpx, nuclei), amass, builds the frontend, generates a `.env` with a random `SECRET_KEY`, runs migrations, creates the `admin` user, grants `NET_RAW` to nmap/naabu, and sets up `systemd` services on Linux.

After install, edit `.env` to add your domain to `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS`, then restart:

```bash
sudo systemctl restart openeasd-web openeasd-worker
```

On macOS, start manually:

```bash
uv run gunicorn openeasd.wsgi:application --bind 0.0.0.0:8000 --workers 2
uv run manage.py dbos_worker   # second terminal (needs PostgreSQL running)
```

### Development Mode

```bash
# Terminal 1: Django + DBOS worker (needs PostgreSQL running)
uv run python main.py

# Terminal 2: Vite dev server (proxies /api/ to Django on port 8000)
cd frontend && npm run dev
# React app at http://localhost:5173
```

### main.py flags

```bash
uv run python main.py --build          # npm build then start
uv run python main.py --build-only     # npm build only
uv run python main.py --port 9000      # custom port
uv run python main.py --no-worker      # web server only (no worker)
```

## CI/CD

GitHub Actions runs on every push to `main` and `v*` tags:
- **pytest**: fast test suite (~922 tests, excludes the 41 slow DNS/RDAP tests in `test_domain_security.py`)
- **bandit**: Python SAST scan
- **pip-audit**: dependency CVE scan
- **Frontend build**: `npm ci && npm run build`
- **Docker build**: amd64 smoke-build on every push
- **Publish to GHCR**: `amd64` images published on every `main` push and version tags

## API

The REST API is served at `/api/` via Django Ninja with JWT Bearer authentication.

- **Docs:** http://localhost:8000/api/docs (OpenAPI/Swagger UI)
- **Auth:** `POST /api/token/pair` → `{access, refresh}` tokens
- **Token refresh:** `POST /api/token/refresh`

## Adding a New Tool

Create a tool app with `tool_meta` in its AppConfig; no core files to modify:

```python
# apps/my_tool/apps.py
from django.apps import AppConfig

class MyToolConfig(AppConfig):
    name = "apps.my_tool"
    label = "my_tool"
    verbose_name = "My Tool"
    tool_meta = {
        "label": "My Tool",
        "runner": "apps.my_tool.scanner.run_my_tool",
        "phase": 6,
        "phase_group": "Port Discovery",
        "requires": ["naabu"],
        "produces_findings": True,
    }
```

Then add `"apps.my_tool"` to `INSTALLED_APPS` in `openeasd/settings.py`. The tool auto-registers in the workflow system.

### Tool App Structure

```
apps/my_tool/
    apps.py         - AppConfig with tool_meta
    models.py       - Empty (uses core Finding/asset models)
    scanner.py      - Orchestrator: collect -> analyze -> save
    collector.py    - Runs binary or probes, returns raw data
    analyzer.py     - Parses data, builds Finding/asset objects
```

## Running Tests

```bash
# Fast tests (excludes slow DNS tests, ~922 tests)
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py

# All tests (~896 total)
uv run pytest tests/
```

## Tech Stack

**Backend:**
- **Django 5**: Web framework
- **Django Ninja**: REST API with OpenAPI docs
- **DBOS**: Durable-execution engine — task queue + scheduler, Postgres-backed (crash-resumable scans)
- **croniter**: Cron parsing for the DBOS user-schedule sweep
- **WhiteNoise**: Serves static files in production (Docker) with gzip compression
- **PostgreSQL** (+ **psycopg 3**): Database — app data and the DBOS checkpoint schema
- **paramiko**: SSH protocol inspection
- **cryptography**: X.509 certificate analysis
- **xhtml2pdf**: PDF report generation
- **django-ninja-jwt**: JWT auth for the Ninja API (built on PyJWT); access + refresh tokens, blacklist on logout

**Frontend:**
- **React 19 + Vite 8**: SPA with hot module replacement
- **Tailwind CSS 3 + shadcn/ui**: Utility-first styling with Radix UI component primitives
- **sonner**: Toast notifications
- Vanilla popstate router (no react-router)

## License

MIT License - see [LICENSE](LICENSE)

## Author

[Rathnakara G N](https://www.linkedin.com/in/rathnakaragn/) and [Ashok S Kamat](https://www.linkedin.com/in/ashokskamat/) / [Cybersecify](https://cybersecify.com)
