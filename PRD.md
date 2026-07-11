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
- Rathnakara G N (co-creator, Cybersecify)
- Ashok S Kamat (co-creator, Cybersecify)

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
- Export reports (CSV, PDF) with optional minimum-severity filter
- Get alerted via Slack/Teams when new issues are found, configurable from the UI without restart
- Continuous per-domain monitoring on configurable interval (6h / 12h / 24h / 48h / weekly)
- Subscan — re-run a subset of tools against an existing scan's assets without repeating discovery
- See trends and insights over time
- JWT-authenticated REST API with OpenAPI docs

## Where

- **Deployment:** Self-hosted (local machine, VPS, Docker, Kubernetes)
- **Access:** Web browser (React SPA at `/`)
- **API:** REST API at `/api/` with Swagger UI at `/api/docs`
- **Distribution:** Open source on GitHub (`ghcr.io/cybersecify/openeasd:latest`)

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
- Async task queue via Huey (later replaced by Django-Q2 in v0.5)
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
- Nuclei Network scanner for network protocol vulnerabilities (Phase 7, service-aware nuclei network templates against non-web ports)
- Nuclei Network runs after service detection, targets non-web ports
- Django Ninja REST API replacing plain JsonResponse views
- JWT Bearer authentication (access + refresh tokens, JTI blacklist)
- Auto-generated OpenAPI docs at `/api/docs`
- `main.py` single-command launcher (auto-migrate, first-run admin creation)
- Dead code cleanup — removed legacy orphaned app directories

**v0.5 — Community Infra + Pipeline Polish + First External Contributors** *(2026-05-31)*
- **First two outside contributors converted on the same day the community infra went live**: `@xiaoke949` shipped HSTS checks (PR #22); `@turfin-logic` shipped backport-aware CVE matching (PR #56). Validated the discovery-via-label hypothesis with hard data — both arrived via GitHub-internal surfaces, zero external referrers.
- **HSTS checks in web_checker** — `missing_hsts` (medium) on HTTPS responses without `Strict-Transport-Security`; `weak_hsts` (low) when `max-age` < 6 months. Contributed by @xiaoke949.
- **Backport-aware CVE matching in nmap analyzer** — distro-backported CVE fixes (Ubuntu USNs, Debian Security Tracker) are recognised and suppressed/demoted via a curated `backports.json`, so already-patched hosts no longer trigger false-positive CVE findings. Contributed by @turfin-logic.
- **Continuous monitoring** — per-domain rescans at configurable intervals (6h/12h/24h/48h/weekly), managed via Django-Q2 schedules
- **Subscan** — re-run specific tools (e.g. Nuclei + TLS Checker) on an existing completed scan's assets without repeating discovery
- **Notifications UI** — Slack and Teams webhooks + severity threshold configurable in-app without restart; per-channel Test button and alert history with pagination
- **Katana URL crawler** (Phase 9) — deep URL discovery on top of httpx's first-level probe
- **CSV/PDF export filter** — `?min_severity=` query param + UI dropdown so exports can be limited to high/critical
- **Setup wizard Copy button** — one-click clipboard for the `docker run` snippet
- **APScheduler replaced by Django-Q2** — one task queue, one scheduler, fewer dependencies; `croniter` added for CRON schedules
- **GitHub Flow workflow adopted** — `feat/` / `fix/` branch + PR + squash-merge; ends the solo-developer direct-push pattern
- **Frontend stack upgrade** — React 19, Vite 8, `@vitejs/plugin-react` 6 (coupled package set in dependabot grouping)
- **Co-founder attribution** — LICENSE, README, `pyproject.toml`, and `PRD.md` updated to credit both co-creators with LinkedIn profile links
- **Community infrastructure** — `CONTRIBUTING.md`, `SECURITY.md` (with GitHub Private Vulnerability Reporting enabled), issue templates (Bug / Feature / New Tool), PR template, Dependabot config with grouped weekly PRs, Discussions tab enabled, repo topics expanded from 7 to 17
- **Tool startup health check** — `tools_healthcheck` management command probes all 8 external tools at container boot, surfaces silent-failure modes early
- **Partial-status watchdog** — scans reaped by the 90-min watchdog are marked `partial` (not `failed`) if any pipeline step completed, preserving the findings that were captured before the reap
- **README hero rewrite** — sharpened "see your domain like an attacker does" framing + live scan screenshot of a real scan
- **README claims-trace audit** — every customer-visible README claim grep-verified against analyzer/scanner code; two drifts corrected (nuclei "319 templates" → timeless phrasing; PyJWT → django-ninja-jwt)
- **Documentation discipline** — every CHANGELOG entry, PR body, and non-trivial commit now captures What / Why / Hypothesis / Evidence (data-oriented vs speculative vs user-driven vs external-signal) so future readers can reconstruct the reasoning

### Planned

**v1.0 — First stable public release**
- Cut a real `v1.0` git tag (current latest tag is `v0.3`; v0.4 and v0.5 work is on `main` but untagged)
- Tag-aligned launch sequence: Show HN + r/netsec + r/blueteamsec post; submit to `awesome-security`, `awesome-pentest`, `awesome-osint`, `awesome-selfhosted`
- Demo GIF in README (30s of a real scan completing) replacing the static screenshot
- Twitter/X seed post with a real (sanitised) finding
- `backports.json` seed dataset expanded beyond Ubuntu LTS / Debian stable to RHEL/Rocky/Alma and Alpine for the noisiest CVE false positives

**v1.x — Collaboration + Usability**
- Finding assignment to team members; comments on findings; email notifications
- Dashboard customization

**v1.x — Advanced Scanning**
- Custom Nuclei template support
- Visual scan diff view (delta between scans rendered as a graph)
- Asset tagging and grouping

**v2.0 — Agentic AI OpenEASD** *(direction set 2026-05-31, design TBD)*

Direction: turn OpenEASD from a scanner that emits findings into an analyst that produces prioritised, contextualised remediation guidance. Move from "here are 76 findings, 3 critical" to "here are the 3 things that actually matter on this surface, here's why, here's the fix in order."

Candidate scopes (specific shape to be defined — these are sketches, not commitments):

- **LLM-powered triage** — feed scan output + asset context + organisation profile into an LLM that produces a ranked "fix this first" list with reasoning, not just raw CVE/severity dumps
- **Chat interface over findings** — "show me everything critical on `staging.example.com`", "summarise this scan in one paragraph", "what's the biggest delta from last week's scan?"
- **Auto-generated tool integrations** — an agent that reads a new scanner tool's docs/GitHub README and produces a draft of the four-file plugin (`apps.py`, `collector.py`, `analyzer.py`, `scanner.py`) for human review
- **Multi-agent recon planning** — a coordinating agent that decides which scanners to run based on initial discovery (e.g., "host runs Postfix on 25 — load the email-relay-misconfig profile" rather than blindly running every Phase-7 tool)
- **Remediation playbooks** — auto-generated step-by-step fix guides per finding type, with reasoning the user can verify

**Hypothesis:** AI turns OpenEASD from "another scanner wrapper" into an analyst-grade tool. The current OSS recon-tool space is saturated with wrappers; analyst-grade output is genuinely scarce. If we ship even one of the candidate scopes well, it becomes the durable differentiation vs. running `nuclei + nmap + subfinder` by hand.

**Status:** planning phase. Specific scope, model selection (local LLM vs API), cost-per-scan envelope, and user opt-in mechanics all undefined. Decision needed before any code is committed.

---

*This document tracks what we're building and why. Technical details live in CLAUDE.md. Per-version detail lives in CHANGELOG.md (with the What/Why/Hypothesis/Evidence discipline).*
