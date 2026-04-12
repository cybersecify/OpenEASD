# OpenEASD

**Open External Attack Surface Detection** - An automated platform for discovering and analyzing your organization's external attack surface.

OpenEASD scans domains to discover subdomains, resolve IPs, scan ports, detect services, and find vulnerabilities across your network attack surface.

## Features

- **Automated pipeline** - 9-step scan workflow from domain to findings
- **Network attack surface scanning** - CVEs, TLS/cert issues, SSH config, protocol vulnerabilities
- **Dynamic workflows** - Create custom scan configurations, enable/disable tools
- **Tool auto-registration** - Add new tools with zero core modification
- **Live scan progress** - Real-time pipeline status with per-tool tracking
- **Scan stop/cancel** - Graceful cancellation between tool steps
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
Phase 5  Service Detection  - Classify ports as web/non-web (core, auto)
Phase 6  Nmap               - CVE scanning via NSE vulners
Phase 7  TLS Checker        - Certificate and cipher analysis
Phase 8  SSH Checker        - SSH configuration audit
Phase 9  Nuclei Network     - Network protocol vulnerability scanning (319 templates)
```

Web scanning tools (httpx, nuclei web, web_checker) are available but disabled
in this release. Re-enable by uncommenting in `settings.py` INSTALLED_APPS.

## Architecture

```
apps/core/              - Infrastructure (never changes)
  assets/               - Network assets: Subdomain, IPAddress, Port
  web_assets/           - Web assets: URL (disabled in non-web focus)
  service_detection/    - Classifies ports as web/non-web (core, always runs)
  findings/             - Unified Finding model
  scans/                - ScanSession, pipeline orchestrator
  workflows/            - Dynamic workflow engine + tool registry
  scheduler/            - APScheduler, daily/weekly scans
  notifications/        - Slack/Teams alerts
  insights/             - Scan summaries, charts
  reports/              - CSV/PDF export
  domains/              - Domain management
  dashboard/            - UI home

apps/                   - Tool apps (add/remove freely)
  domain_security/      - DNS, email, RDAP checks
  subfinder/            - Passive subdomain enumeration
  dnsx/                 - DNS resolution
  naabu/                - Port scanning
  nmap/                 - CVE scanning (NSE vulners)
  tls_checker/          - TLS/cert/cipher analysis
  ssh_checker/          - SSH configuration audit
  nuclei_network/       - Network protocol vuln scanning
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
git clone https://github.com/cybersecify/OpenEASD.git
cd OpenEASD

# Install dependencies
uv sync --extra dev

# Copy environment config
cp .env.example .env

# Install ProjectDiscovery tools
pdtm -install-all

# Setup database
uv run manage.py migrate
uv run manage.py createsuperuser

# Run (starts both web server + task worker)
uv run python main.py
```

Open http://localhost:8000, add a domain, and start scanning.

### Install External Tools

```bash
# ProjectDiscovery tools (subfinder, dnsx, naabu, nuclei)
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
        "phase": 6,
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
- **paramiko** - SSH protocol inspection
- **cryptography** - X.509 certificate analysis

## License

MIT License - see [LICENSE](LICENSE)

## Author

[Rathnakara G N](https://cybersecify.com) / [CyberSecify](https://cybersecify.com)
