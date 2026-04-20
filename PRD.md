# PRD — OpenEASD (Open External Attack Surface Detection)

## Why

Organizations don't know what they expose to the internet. Subdomains, open ports, misconfigured DNS, expired certificates, and known CVEs sit undetected until an attacker finds them first.

Existing commercial tools (Shodan, Censys, AttackSurfaceMapper) are expensive, complex, or require manual effort. There is no simple, self-hosted, open-source tool that automates the full external attack surface scan — from domain to vulnerability — in one workflow.

**OpenEASD exists to give security teams and solo practitioners a free, automated way to continuously monitor their external attack surface.**

## Who

**Primary users:**
- Security engineers / penetration testers managing external assets
- Small security teams without budget for commercial ASM tools
- Solo practitioners / bug bounty hunters scanning their own targets
- DevOps / SREs who want visibility into what's exposed

**Stakeholders:**
- Open source community (contributors, users)
- Rathnakara G N (creator, Cybersecify)

## What

A self-hosted web platform that automatically discovers and monitors an organization's external attack surface. Users add domains, and OpenEASD:

1. Checks domain security posture (DNS, email, RDAP)
2. Discovers all subdomains (passive + active)
3. Resolves them to IP addresses
4. Scans for open ports
5. Classifies web vs non-web services
6. Detects known vulnerabilities (CVEs, network protocols, TLS, SSH)
7. Scans web services for security headers, cookies, CORS, and web vulnerabilities

**Core capabilities:**
- Add domains and run on-demand or scheduled scans
- View findings by severity with remediation guidance
- Track finding lifecycle (open → acknowledged → resolved)
- Export reports (CSV, PDF)
- Get alerted via Slack/Teams when new issues are found
- See trends and insights over time
- JWT-authenticated REST API with OpenAPI docs

## Where

- **Deployment:** Self-hosted (local machine, VPS, Docker)
- **Access:** Web browser (React SPA at `/`)
- **API:** REST API at `/api/` with Swagger UI at `/api/docs`
- **Distribution:** Open source on GitHub

## When

### Delivered

**v0.1 — Foundation**
- Web dashboard with domain management
- Domain security scanning (DNS, email, RDAP checks)
- Subdomain discovery (subfinder)
- Scheduled daily scans
- Insights and trend tracking
- Slack/Teams alerting

**v0.2 — Full Pipeline + Stability**
- Complete scan pipeline (domain security → subfinder → dnsx → naabu → service detection → nmap → tls_checker → ssh_checker → httpx → nuclei → web_checker)
- Unified finding model across all tools
- Finding lifecycle tracking (open, acknowledged, resolved, false positive)
- CSV and PDF report export
- Async task queue via Huey (no more silent thread crashes)
- Configurable scan workflows (enable/disable tools)
- Performance improvements (query optimization)

**v0.3 — React SPA + Modern UI**
- Full React 18 + Vite frontend replacing HTMX/Alpine legacy stack
- Dark theme throughout
- Live scan progress with per-tool step tracking
- Workflow management UI (create, edit, toggle steps)
- Paginated findings with filtering by severity/source/status
- Insights page with trend charts

**v0.4 — Network Vuln Expansion + Active Recon**
- Amass integration for active subdomain enumeration (Phase 2)
- Nuclei Network scanner for network protocol vulnerabilities (Phase 7, 319 templates)
- Nuclei Network runs after service detection, targets non-web ports

**v1.0 — Stable Public Release**
- Django Ninja REST API replacing plain JsonResponse views
- JWT Bearer authentication (access + refresh tokens, JTI blacklist)
- Auto-generated OpenAPI docs at `/api/docs`
- `main.py` single-command launcher (auto-migrate, first-run admin creation)
- ~598 automated tests covering all modules
- Dead code cleanup — removed 5 legacy orphaned app directories

### Planned

**v1.1 — Deployment Ready**
- Docker Compose setup (one-command deploy)
- Environment configuration guide (`.env.example`)
- Production deployment guide (nginx + gunicorn)
- GitHub Actions CI pipeline

**v1.2 — Collaboration + Usability**
- Finding assignment to team members
- Comments on findings
- Email notifications
- Dashboard customization

**v1.3 — Advanced Scanning**
- Custom Nuclei template support
- Scan diff view (visual delta between scans)
- Asset tagging and grouping

---

*This document tracks what we're building and why. Technical details live in CLAUDE.md.*
