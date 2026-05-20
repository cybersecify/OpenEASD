# OpenEASD

[![GitHub Stars](https://img.shields.io/github/stars/cybersecify/OpenEASD?style=social)](https://github.com/cybersecify/OpenEASD/stargazers)
[![CI](https://github.com/cybersecify/OpenEASD/actions/workflows/ci.yml/badge.svg)](https://github.com/cybersecify/OpenEASD/actions/workflows/ci.yml)
[![Docker Image](https://ghcr-badge.egpl.dev/cybersecify/openeasd/latest_tag?trim=major&label=ghcr.io)](https://github.com/cybersecify/OpenEASD/pkgs/container/openeasd)

**Open External Attack Surface Detection** - An automated platform for discovering and analyzing your organization's external attack surface.

OpenEASD scans domains to discover subdomains, resolve IPs, scan ports, detect services, and find vulnerabilities across your network attack surface.

## Features

- **Automated pipeline** — 13-tool scan workflow from domain to findings
- **Network attack surface scanning** — CVEs, TLS/cert issues, SSH config, network protocol vulnerabilities
- **Dynamic workflows** — Create custom scan configurations, enable/disable tools per workflow
- **Tool auto-registration** — Add new tools with zero core modification
- **Live scan progress** — Real-time pipeline status with per-tool step tracking
- **Scan stop/cancel** — Graceful cancellation between tool steps
- **Unified findings** — All tools write to a single Finding model with lifecycle tracking
- **Reports** — CSV and PDF export
- **Alerts** — Slack and Microsoft Teams notifications
- **Scheduling** — One-time, recurring, and daily automated scans
- **JWT auth** — Stateless Bearer token authentication with refresh token rotation
- **Forced password change** — Default `admin/admin` password must be changed on first login

## Scan Pipeline

```
Phase 1  Domain Security    - DNS, email (SPF/DMARC/DKIM), RDAP checks
Phase 2  Subfinder          - Passive subdomain enumeration
Phase 2  Amass              - Active subdomain enumeration
Phase 3  DNSx               - DNS resolution, public IP filtering
Phase 4  Naabu              - TCP port scanning (top 100)
Phase 5  Service Detection  - Classify ports as web/non-web via nmap -sV (auto)
Phase 7  Nmap               - CVE scanning via NSE vulners (non-web ports)
Phase 7  TLS Checker        - Certificate, cipher, and protocol analysis
Phase 7  SSH Checker        - SSH configuration audit
Phase 7  Nuclei Network     - Network protocol vulnerability scanning (319 templates)
Phase 8  httpx              - Web probing, URL discovery
Phase 9  Nuclei             - Web vulnerability scanning (community templates)
Phase 9  Web Checker        - Security headers, cookies, CORS analysis
```

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
  scheduler/            - APScheduler, daily/weekly scans, stuck scan watchdog
  notifications/        - Slack/Teams alerts
  insights/             - Scan summaries, charts
  reports/              - CSV/PDF export
  domains/              - Domain management
  dashboard/            - UI home

apps/                   - Tool apps (add/remove freely)
  domain_security/      - DNS, email, RDAP checks
  subfinder/            - Passive subdomain enumeration
  amass/                - Active subdomain enumeration
  dnsx/                 - DNS resolution
  naabu/                - Port scanning
  nmap/                 - CVE scanning (NSE vulners)
  tls_checker/          - TLS/cert/cipher analysis
  ssh_checker/          - SSH configuration audit
  nuclei_network/       - Network protocol vuln scanning
  httpx/                - Web probing
  nuclei/               - Web vulnerability scanning
  web_checker/          - Security headers, cookies, CORS

frontend/               - React 18 + Vite SPA
  src/pages/            - Page components
  src/components/       - Shared UI primitives (Badge, Spinner, Pagination, ConfirmButton)
  src/components/ui/    - shadcn/ui primitives (Button, Card, Table, AlertDialog, …)
  src/hooks/            - useFetch, usePolling
  src/api/client.js     - JWT apiFetch wrapper
  src/auth.js           - localStorage token helpers
```

## Quick Start

### Docker (recommended)

```bash
docker run -d \
  -p 8000:8000 \
  -v openeasd-data:/app/data \
  -v openeasd-logs:/app/logs \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  --cap-add NET_RAW \
  --restart unless-stopped \
  --name openeasd \
  ghcr.io/cybersecify/openeasd:latest
```

Open http://localhost:8000 — log in with `admin` / `admin`. You will be forced to set a new password before accessing the app.

#### Update to latest

```bash
docker pull ghcr.io/cybersecify/openeasd:latest
docker stop openeasd && docker rm openeasd
# re-run the docker run command above — volumes preserve all data
```

#### Environment variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | insecure default | Django secret key — **set this in production** |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated hostnames (add your server IP/domain) |
| `CSRF_TRUSTED_ORIGINS` | — | Required if accessing via a domain, e.g. `https://openeasd.example.com` |
| `DEBUG` | `False` | Set `True` only for local development |
| `DB_NAME` | `data/openeasd.db` | SQLite path relative to `/app` |
| `SLACK_WEBHOOK_URL` | — | Slack incoming webhook for scan alerts |
| `MS_TEAMS_WEBHOOK_URL` | — | Teams incoming webhook for scan alerts |
| `ALERT_SEVERITY_THRESHOLD` | `high` | Minimum severity to trigger alerts (`critical`/`high`/`medium`/`low`) |
| `SCAN_DAILY_HOUR` | `2` | Hour for daily scheduled scans (24h, UTC) |
| `SCAN_DAILY_MINUTE` | `0` | Minute for daily scheduled scans |

### Deploy on Oracle Cloud Free Tier (Always Free)

Oracle Cloud's Ampere A1 instance (4 OCPUs, 24GB RAM) is permanently free and ideal for self-hosting — full root access, no platform restrictions on security tools.

**1. Create the VM**

In Oracle Cloud Console → Compute → Instances → Create Instance:
- Image: **Ubuntu 22.04**
- Shape: **VM.Standard.A1.Flex** (Ampere) — 2 OCPUs, 12GB RAM
- Add your SSH public key

**2. Open port 8000**

In the instance's VCN Security List → Add Ingress Rule: TCP port `8000`, source `0.0.0.0/0`.

Then SSH in and open the OS firewall:
```bash
ssh ubuntu@<PUBLIC_IP>
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 8000 -j ACCEPT
sudo netfilter-persistent save
```

**3. Install Docker**
```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker ubuntu && newgrp docker
```

**4. Run OpenEASD**
```bash
docker run -d \
  -p 8000:8000 \
  -v openeasd-data:/app/data \
  -v openeasd-logs:/app/logs \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e ALLOWED_HOSTS="<PUBLIC_IP>,localhost" \
  --cap-add NET_RAW \
  --restart unless-stopped \
  --name openeasd \
  ghcr.io/cybersecify/openeasd:latest
```

Open `http://<PUBLIC_IP>:8000`. The `arm64` image runs natively on Ampere hardware.

### Prerequisites (from source)

- Python 3.11+
- Node.js 18+ (for frontend)
- [uv](https://docs.astral.sh/uv/) (Python package manager)
- [ProjectDiscovery tools](https://github.com/projectdiscovery) (`pdtm` recommended)
- nmap
- amass (optional, for active subdomain enumeration)

### Install

```bash
# Clone
git clone https://github.com/cybersecify/OpenEASD.git
cd OpenEASD

# Install Python dependencies
uv sync

# Install ProjectDiscovery tools
curl -sL https://raw.githubusercontent.com/projectdiscovery/pdtm/main/scripts/install.sh | bash
pdtm -install-all

# nmap (macOS)
brew install nmap
# nmap (Ubuntu/Debian)
sudo apt install nmap

# Build frontend
cd frontend && npm install && npm run build && cd ..

# Run (auto-migrates, creates admin/admin on first run)
uv run python main.py
```

Open http://localhost:8000, log in with `admin/admin`, change the password, add a domain, and start scanning.

### Development Mode

```bash
# Terminal 1 — Django + Django-Q2 worker
uv run python main.py

# Terminal 2 — Vite dev server (proxies /api/ to Django on port 8000)
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
- **pytest** — fast test suite (~522 tests, excludes slow DNS/RDAP tests)
- **bandit** — Python SAST scan
- **pip-audit** — dependency CVE scan
- **Frontend build** — `npm ci && npm run build`
- **Docker build** — amd64 smoke-build on every push
- **Publish to GHCR** — multi-arch (`amd64` + `arm64`) image published on every `main` push and version tags

## API

The REST API is served at `/api/` via Django Ninja with JWT Bearer authentication.

- **Docs:** http://localhost:8000/api/docs (OpenAPI/Swagger UI)
- **Auth:** `POST /api/token/pair` → `{access, refresh}` tokens
- **Token refresh:** `POST /api/token/refresh`

## Adding a New Tool

Create a tool app with `tool_meta` in its AppConfig — no core files to modify:

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
# Fast tests (excludes slow DNS tests, ~522 tests)
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py

# All tests (~563 total)
uv run pytest tests/
```

## Tech Stack

**Backend:**
- **Django 5** — Web framework
- **Django Ninja** — REST API with OpenAPI docs
- **Django-Q2** — Background task queue (ORM broker, tasks stored in Django DB)
- **WhiteNoise** — Serves static files in production (Docker) with gzip compression
- **SQLite** — Database (dev), configurable via `DB_NAME`
- **paramiko** — SSH protocol inspection
- **cryptography** — X.509 certificate analysis
- **xhtml2pdf** — PDF report generation
- **PyJWT** — JWT token creation and validation

**Frontend:**
- **React 18 + Vite** — SPA with hot module replacement
- **Tailwind CSS 3 + shadcn/ui** — Utility-first styling with Radix UI component primitives
- **sonner** — Toast notifications
- Vanilla popstate router (no react-router)

## License

MIT License - see [LICENSE](LICENSE)

## Author

[Rathnakara G N](https://cybersecify.com) / [CyberSecify](https://cybersecify.com)
