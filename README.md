# OpenEASD

**Open External Attack Surface Detection** - An automated platform for discovering and analyzing your organization's external attack surface.

OpenEASD scans domains to discover subdomains, resolve IPs, scan ports, detect services, and find vulnerabilities across both web and non-web attack surfaces.

## Features

- **Automated pipeline** - 11-step scan workflow from domain to findings
- **Web + non-web scanning** - Separate analysis paths for web and network services
- **Dynamic workflows** - Create custom scan configurations, enable/disable tools
- **Tool auto-registration** - Add new tools with zero core modification
- **Live scan progress** - Real-time pipeline status with per-tool tracking
- **Unified findings** - All tools write to a single Finding model
- **Reports** - CSV and PDF export
- **Alerts** - Slack and Microsoft Teams notifications
- **Scheduling** - One-time, recurring, and daily automated scans

## Scan Pipeline

```
Phase 1  Domain Security    - DNS, email (SPF/DMARC/DKIM), RDAP checks
Phase 2  Subfinder          - Passive subdomain enumeration
Phase 3  DNSx               - DNS resolution, public IP filtering
Phase 4  Naabu              - TCP port scanning (top 100)
Phase 5  Service Detection  - Classify ports as web/non-web
Phase 6  HTTPx              - Web probing, URL discovery (CDN-aware)
Phase 7  Nmap               - CVE scanning on non-web ports
Phase 7  TLS Checker        - Certificate and cipher analysis (all ports)
Phase 7  SSH Checker        - SSH configuration audit
Phase 8  Nuclei             - Web vulnerability scanning (community templates)
Phase 8  Web Checker        - Security headers, cookies, CORS, disclosure
```

## Architecture

```
apps/core/          - Infrastructure (never changes)
  assets/           - Network assets: Subdomain, IPAddress, Port
  web_assets/       - Web assets: URL
  service_detection/- Classifies ports as web/non-web
  findings/         - Unified Finding model
  scans/            - ScanSession, pipeline orchestrator
  workflows/        - Dynamic workflow engine + tool registry
  scheduler/        - APScheduler, daily/weekly scans
  notifications/    - Slack/Teams alerts
  insights/         - Scan summaries, charts
  reports/          - CSV/PDF export
  domains/          - Domain management
  dashboard/        - UI home

apps/               - Tool apps (add/remove freely)
  domain_security/  subfinder/  dnsx/  naabu/  httpx/
  nmap/  tls_checker/  ssh_checker/  nuclei/  web_checker/
```

## Quick Start

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (Python package manager)
- [ProjectDiscovery tools](https://github.com/projectdiscovery) (`pdtm` recommended)
- nmap

### Install

```bash
# Clone
git clone https://github.com/cybersecify/openeasd-django.git
cd openeasd-django

# Install dependencies
uv sync --extra dev

# Copy environment config
cp .env.example .env

# Install ProjectDiscovery tools
pdtm -install-all

# Setup database
uv run manage.py migrate
uv run manage.py createsuperuser

# Run
uv run manage.py runserver
```

Open http://localhost:8000, add a domain, and start scanning.

### Install External Tools

```bash
# ProjectDiscovery tools (subfinder, dnsx, naabu, httpx, nuclei)
curl -sL https://raw.githubusercontent.com/projectdiscovery/pdtm/main/scripts/install.sh | bash
pdtm -install-all

# nmap (macOS)
brew install nmap

# nmap (Ubuntu/Debian)
sudo apt install nmap
```

## Adding a New Tool

Create a tool app with `tool_meta` in its AppConfig - no core files to modify:

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
        "phase": 7,
        "requires": ["naabu"],
        "produces_findings": True,
    }
```

Then add `"apps.my_tool"` to `INSTALLED_APPS` in settings. The tool auto-registers in the workflow system.

### Tool App Structure

```
apps/my_tool/
    apps.py         - AppConfig with tool_meta
    models.py       - Empty (uses core Finding model)
    scanner.py      - Orchestrator: collect -> analyze -> save
    collector.py    - Runs binary or probes, returns raw data
    analyzer.py     - Parses data, builds Finding objects
```

## Running Tests

```bash
# Fast tests (excludes slow DNS tests)
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py

# All tests
uv run pytest tests/
```

## Tech Stack

- **Django 5** - Web framework (plain views, no DRF)
- **HTMX** - Server-driven UI updates
- **Alpine.js** - Client-side interactivity
- **Tailwind CSS** - Styling (CDN)
- **Chart.js** - Visualizations
- **Huey** - Background task queue
- **SQLite** - Database (dev), configurable via `DB_NAME`

## License

MIT License - see [LICENSE](LICENSE)

## Author

[Rathnakara G N](https://cybersecify.com) / [CyberSecify](https://cybersecify.com)
