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
2. Discovers all subdomains
3. Resolves them to IP addresses
4. Scans for open ports
5. Classifies web vs non-web services
6. Detects known vulnerabilities (CVEs) on non-web ports

**Core capabilities:**
- Add domains and run on-demand or scheduled scans
- View findings by severity with remediation guidance
- Track finding lifecycle (open → acknowledged → resolved)
- Export reports (CSV, PDF)
- Get alerted via Slack/Teams when new issues are found
- See trends and insights over time

## Where

- **Deployment:** Self-hosted (local machine, VPS, Docker)
- **Access:** Web browser (dashboard)
- **Distribution:** Open source on GitHub

## When

### Delivered

**v0.1 — Foundation**
- Web dashboard with domain management
- Domain security scanning (DNS, email, RDAP checks)
- Subdomain discovery
- Scheduled daily scans
- Insights and trend tracking
- Slack/Teams alerting

**v0.2 — Full Pipeline + Stability**
- Complete 6-phase scan pipeline (domain security → subfinder → dnsx → naabu → httpx → nmap)
- Unified finding model across all tools
- Finding lifecycle tracking (open, acknowledged, resolved, false positive)
- CSV and PDF report export
- Async task queue (no more silent thread crashes)
- Configurable scan workflows (enable/disable tools)
- 240 automated tests
- Performance improvements (query optimization)

### Planned

**v0.3 — Deployment Ready**
- Docker Compose setup (one-command deploy)
- Environment configuration guide
- README with install/usage instructions
- LICENSE file
- `.env.example` for easy configuration

**v0.4 — Web Vulnerability Scanning**
- Re-enable Nuclei scanner for web ports
- Web-specific findings (XSS, SQLi, misconfigurations)
- SSL/TLS certificate checking

**v0.5 — Collaboration + Usability**
- Finding assignment to team members
- Comments on findings
- Email notifications
- Dashboard customization

**v1.0 — Stable Public Release**
- Stable architecture (no breaking changes)
- Complete documentation
- Contributor guidelines
- Production deployment guide

---

*This document tracks what we're building and why. Technical details live in CLAUDE.md.*
