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

OpenEASD wraps the open-source recon tools security teams already use: `subfinder`, `amass`, `alterx`, `dnsx`, `subzy`, `cloud_enum`, `naabu`, `nmap`, `httpx`, `gau`, `katana`, `nuclei`, `gitleaks`, behind a single web UI with scheduling, alerts, and findings tracking. Thirty tools across DNS/DNSSEC, historical DNS records (passive; A/AAAA/MX a domain has resolved to over time), email (SPF/DMARC/DKIM/MTA-STS/open-relay), TLS, SSH, ports, CVEs, subdomain takeover, ASN/IP-range discovery, historical URLs, cloud assets, exposed secrets in JavaScript, leaked secrets in public GitHub (passive; searches GitHub's code-search API for the org's committed credentials and runs gitleaks over the hits — bring-your-own GitHub token), public-source infrastructure exposure (passive; internal hostnames, cloud buckets, and API endpoints leaked in the org's public GitHub repos), infostealer-log exposure (via Hudson Rock's keyless Cavalier API), data-breach exposure (passive; free XposedOrNot tier out of the box, authoritative with a bring-your-own Have I Been Pwned key), Shodan-sourced exposure (passive; free InternetDB tier out of the box, richer with a bring-your-own Shodan key), lookalike / TLD-squat domain detection (passive; phishing infrastructure and brand abuse targeting your domain), technology fingerprinting, web hygiene, and CVE prioritisation (EPSS + CISA KEV). Run a **passive scan** (public-source only, no authorization needed) or an **active scan** (probes the target, authorization required). Self-hosted, MIT-licensed, one `docker run` (single image). Results stay on your machine — unless you enable the optional Cloudflare Workers AI analysis (off by default, explicit consent required), which sends finding data to your own Cloudflare account.

Optionally, OpenEASD can rank each scan's findings by exploitability and explain why (a "fix these first" list with per-finding rationale), schedule targeted follow-up scan steps based on what was found, and write plain-language report and alert summaries — using Cloudflare Workers AI with your own account (credentials saved in Django admin (AI settings), or via `CLOUDFLARE_ACCOUNT_ID` + `CLOUDFLARE_API_TOKEN` env vars). Off by default; enabling it requires explicit consent in the UI, every call is audit-logged (never the prompt or response contents), and active follow-up scanning still requires the same domain authorization as manual scans.

Built by [Rathnakara GN](https://www.linkedin.com/in/rathnakaragn/) and [Ashok Kamat](https://www.linkedin.com/in/ashokskamat/) of [Cybersecify](https://cybersecify.com), the same tool we run in engagements and on our own infrastructure.

## Who this is for

- **In-house security engineers and IT-doing-security teams** at small-to-mid orgs scanning their own external surface
- **Small security consultancies** monitoring a handful of clients
- **Bug bounty hunters** who want a unified view of recon output across programs they're authorised to test
- **Solo self-hosters and security learners** auditing their own infra

## Who this isn't for

- **Enterprise SOCs**: no RBAC, SAML, or multi-tenant support (single-user by design)
- **Anyone needing to scan domains they don't own or aren't authorised to test**: OpenEASD is intentionally not a "scan-anyone" hosted service. Running it implies you own or have written authorisation for your targets

## Compliance evidence

OpenEASD is not a compliance product and does not make anyone certified. What it does produce is the external scanning evidence auditors ask for, dated and exportable, instead of a screenshot taken the week before the audit.

| What an auditor asks for | Where it comes from |
| --- | --- |
| Scanning happens on a defined cadence | Per domain monitoring (6h / 12h / 24h / 48h / weekly) plus one time and recurring schedules, with every run recorded |
| An inventory of internet facing assets | Persistent asset inventory (Django admin): subdomains, IPs, ports and URLs deduplicated across scans, each with first seen, last seen, and active or gone status |
| Findings ranked by real world risk | Severity enriched with EPSS exploit probability and CISA KEV flags, plus an exposure score and grade with movement against the previous scan |
| Evidence that findings get triaged and closed | Issue status (open, acknowledged, in progress, resolved, false positive, accepted risk) with owner, resolution note, first seen, last seen and resolved date |
| Something you can hand over | Per scan CSV export, including the Issue Register |
| Authority to scan the target | Each domain carries a recorded authorization (owner, written consent or bug bounty) with who gave it and when, enforced server side before any active scan |

Control references that usually apply: ISO/IEC 27001:2022 Annex A 8.8 (technical vulnerability management) and A 5.9 (inventory of information and other associated assets); SOC 2 Trust Services Criteria CC7.1 (detection and monitoring) and CC6.6 (boundary protection). Auditors word their requests differently, so treat this as a starting point, not a mapping to cite.

What it does not do: it is not a penetration test, so it does not satisfy requirements that call for one, such as Amazon SP-API Data Protection Policy reviews or most enterprise security questionnaires. It does not look at internal networks, cloud configuration posture, or the policy and process side of either framework.

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

Every push to `main` and every `v*` tag triggers
[`.github/workflows/ci.yml`](.github/workflows/ci.yml), which builds
the `linux/amd64` single image and publishes to
`ghcr.io/cybersecify/openeasd`. The build is reproducible from the
public source; the published image carries:

- **SBOM** (Software Bill of Materials, SPDX format): every package in
  the image, retrievable via `docker buildx imagetools inspect`
- **SLSA provenance attestation**: cryptographic proof that the image
  was built by this repo's GitHub Actions, not swapped or rebuilt
  elsewhere

```bash
# The published image carries its own SBOM + provenance:
docker buildx imagetools inspect ghcr.io/cybersecify/openeasd:latest --format '{{ json .SBOM }}'
docker buildx imagetools inspect ghcr.io/cybersecify/openeasd:latest --format '{{ json .Provenance }}'
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
docker build --target singleimage -t openeasd .
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

The primary deploy is a **single Docker image** (embedded PostgreSQL + gunicorn + DBOS worker in one container). The `/data` volume is mandatory (Postgres data + logs live there):

```bash
docker run -d --name openeasd -p 8000:8000 -v openeasd-data:/data \
  -e SECRET_KEY=<long random> -e DB_PASSWORD=<strong> -e DEBUG=False \
  -e ALLOWED_HOSTS=<host,localhost> ghcr.io/cybersecify/openeasd:latest
# or: docker compose -f docker-compose.singleimage.yml up -d --build
```

For a privilege-separated / scalable setup, use the 3-tier path (PostgreSQL + web + worker via `docker compose up -d --build`); see [Deployment](#deployment).

Open http://localhost:8000 → log in with `admin` / `admin` (you'll be forced to set a new password) → add a domain → run a scan. Full env-var reference, update path, and Kubernetes manifests are under [Deployment](#deployment).

## Features

- **Automated pipeline**: 30-tool scan workflow from domain to findings
- **Network attack surface scanning**: CVEs, TLS/cert issues, SSH config, network protocol vulnerabilities
- **CVE prioritisation**: EPSS exploit-probability scores + CISA KEV (known-exploited-in-the-wild) flags enrich CVE findings in place, so you triage by real-world risk rather than severity alone
- **Dynamic workflows**: predefined scan modes (Passive Light/Deep, Active Light, Full) plus a custom tool selection per scan
- **Tool auto-registration**: Add new tools with zero core modification
- **Live scan progress**: Real-time pipeline status with per-tool step tracking
- **Scan stop/cancel**: Graceful cancellation between tool steps
- **Unified findings**: All tools write to a single Finding model with lifecycle tracking
- **Asset inventory**: A persistent, deduplicated view of your attack surface across scans — every subdomain/IP/port/URL with first-seen / last-seen / active-or-gone status; pivot from any asset to its findings and scan history (persistent inventory, browsable in Django admin)
- **Continuous monitoring**: Per-domain rescans on a configurable schedule (6h / 12h / 24h / 48h / weekly)
- **Subscan**: Re-run specific tools on existing scan assets without full rediscovery
- **Reports**: CSV export
- **Alerts**: Slack and Teams webhooks with configurable severity threshold; alert history in Django admin
- **Scheduling**: One-time, recurring, and daily automated scans
- **Domain authorization enforcement**: Each domain requires a recorded authorization (owner / written consent / bug bounty) before an active scan can start; passive-only scans are exempt. Enforced server-side in the scan-start view
- **Session auth**: Django session login; the default `admin/admin` must be changed on first login

## Scan Pipeline

```
── Domain Posture ───────────────────────────────────────────────────────────
Phase 1  Domain Security   - DNS, DNSSEC chain-of-trust, email auth
                             (SPF/DMARC/DKIM/TLS-RPT/BIMI), RDAP checks (passive;
                             public resolvers + rdap.org — no auth needed)
Phase 1  Domain Probes      - Active target probes (needs authorization): AXFR
                             zone transfer, SMTP open-relay, MTA-STS policy fetch
Phase 1  DNS History        - Historical A/AAAA/MX records via a passive-DNS
                             dataset (passive; BYO DNS_HISTORY_API_URL)

── Brand Threat ─────────────────────────────────────────────────────────────
Phase 1  TLD Squatting          - Lookalike / tldsquatting domain detection (passive;
                             registered lookalikes via public DNS — phishing/brand abuse)
Phase 13 ASN Clustering     - Groups registered lookalikes by shared hosting ASN
                             (Team Cymru, passive) — coordinated phishing infra

── Credential Exposure ──────────────────────────────────────────────────────
Phase 2  Hudson Rock        - Infostealer-log exposure via Hudson Rock's keyless
                             Cavalier API (aggregate counts only, no plaintext)
Phase 2  GitHub Secrets      - Leaked secrets in public GitHub via gitleaks
                             (passive; BYO GITHUB_TOKEN, redacted before storage)
Phase 2  Breach Check       - Data-breach exposure via XposedOrNot (free/keyless)
                             or Have I Been Pwned (BYO key); counts only, no PII

── Asset Discovery ──────────────────────────────────────────────────────────
Phase 3  Subfinder         - Passive subdomain enumeration
Phase 3  Amass             - Active subdomain enumeration
Phase 3  Alterx            - Subdomain permutation from discovered subdomains
Phase 3  ASN Discovery     - Owned ASN/CIDR ranges via amass intel (reports only)
Phase 3  GitHub Org Recon  - Infra references (hostnames/buckets/API endpoints) in
                             the org's public GitHub repos (passive; BYO token opt.)
Phase 4  DNSx              - DNS resolution, public IP filtering

── Asset Exposure ───────────────────────────────────────────────────────────
Phase 5  Takeover Check    - Subdomain takeover detection via subzy (dangling DNS)
Phase 5  Cloud Assets      - Public S3/Azure/GCP bucket enumeration (cloud_enum)

── Port Discovery ───────────────────────────────────────────────────────────
Phase 6  Naabu             - TCP port scanning (top 100; CDN edge IPs excluded)
Phase 6  Shodan            - Passive exposure intel: ports/services/CVEs per IP (free InternetDB; BYO key for full API)
Phase 7  Service Detection - Classify ports as web/non-web via nmap -sV (auto)

── Network Exposure ─────────────────────────────────────────────────────────
Phase 8  Nmap              - CVE scanning via NSE vulners (non-web ports)
Phase 8  TLS Checker       - Certificate, cipher, and protocol analysis
Phase 8  SSH Checker       - SSH configuration audit
Phase 8  Nuclei Network    - Network protocol vuln templates (non-web ports)

── Web Exposure ─────────────────────────────────────────────────────────────
Phase 9  httpx             - Web probing, URL discovery, technology fingerprinting
Phase 10 Historical URLs   - Archived URL discovery via gau
Phase 11 Katana            - Deep URL crawl on top of httpx
Phase 12 Nuclei            - Web vulnerability scanning (community templates)
Phase 12 Web Checker       - Security headers, cookies, CORS; security.txt (RFC 9116)
Phase 12 JS Secrets        - Hardcoded secrets in fetched JavaScript via gitleaks

── Prioritization ───────────────────────────────────────────────────────────
Phase 13 CVE Intel         - Enrich CVE findings with EPSS + CISA KEV

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
(saved in Django admin (AI settings), or `CLOUDFLARE_ACCOUNT_ID` / `CLOUDFLARE_API_TOKEN`
env vars) **and** an operator enables it with explicit consent. With it off — the
default — the pipeline ends at Phase 13 and nothing leaves your machine. Every AI
call is recorded in an audit log (time, scan, purpose, model, token counts,
finding IDs); prompt and response contents are never stored.

## Architecture

```
apps/mvp/                 - Server-rendered UI: Django views + templates, vendored Bulma + HTMX, session auth

apps/core/                - Infrastructure (never changes), grouped in three layers
  console/                - dashboard, insights, reports (CSV), notifications (Slack/Teams),
                            ai (Cloudflare Workers AI, BYOK), credentials, observability
  engine/                 - scans, workflows (+ tool registry), durable (DBOS), scheduler,
                            service_detection (core, always runs), verification
  data/                   - domains, assets, web_assets, findings, issues, asset_inventory

apps/<tool>/              - 29 tool apps (add/remove freely): domain_security, domain_probe,
                            dns_history, tldsquatting, hudson_rock, github_secrets, breach_check,
                            subfinder, amass, asn_discovery, github_recon, alterx, dnsx,
                            takeover_check, cloud_assets, naabu, shodan, nmap, tls_checker,
                            ssh_checker, nuclei_network, httpx, historical_urls, katana, nuclei,
                            web_checker, js_secrets, cve_intel, asn_cluster
```

See `manage.py render_pipeline_diagram` and [`docs/03-system.md`](docs/03-system.md) for the full pipeline.

## Deployment

### Single Docker image (primary)

One container runs embedded PostgreSQL + gunicorn + the DBOS worker. The `/data` volume is mandatory:

```bash
docker run -d --name openeasd -p 8000:8000 -v openeasd-data:/data \
  -e SECRET_KEY=<long random> -e DB_PASSWORD=<strong> -e DEBUG=False \
  -e ALLOWED_HOSTS=<host,localhost> ghcr.io/cybersecify/openeasd:latest
# or: docker compose -f docker-compose.singleimage.yml up -d --build
```

Trade-off: scanner tools and `NET_RAW` share the web process (no privilege separation), and web/worker cannot scale independently. Use the 3-tier path below when that matters.

### Docker Compose, 3-tier (privilege-separated / scalable alternative)

OpenEASD runs as three services — **PostgreSQL + web + worker**. Edit the
secrets in `docker-compose.yml` (`SECRET_KEY`, `DB_PASSWORD`, `ALLOWED_HOSTS`),
then:

```bash
docker compose up -d --build
```

- `db` — PostgreSQL 17 (app data + the DBOS durable-execution schema)
- `web` — the slim `openeasd-web` image (server-rendered UI + synchronous CSV reports; no scanner tools)
- `worker` — the `openeasd-worker` image (DBOS worker + the full scanner matrix, `NET_RAW`)

> **For internet-facing or scaled deployments, run all three tiers.** Keeping
> `web`, `worker`, and `db` as separate containers is deliberate:
> - **Privilege separation** — the internet-facing `web` image carries **no
>   scanner tools and no `NET_RAW`**, so a compromised web surface doesn't
>   inherit the offensive toolkit or raw-socket access (those live only on the
>   worker, which isn't exposed).
> - **Fault isolation** — nuclei/amass are memory-hungry; if one is OOM-killed
>   it takes down only a worker, not the UI.
> - **Independent scaling** — Postgres has no single-writer lock, so you can run
>   multiple `worker` replicas pulling the same DBOS queue for scan throughput
>   while the `web` tier scales separately for HTTP load.
>
> Collapsing `web` + `worker` into one container is possible for a small,
> trusted, single-user evaluation, but it puts the scanner tools and `NET_RAW`
> on the exposed process — **not recommended for internet-facing deployments.**
> Keep `db` as its own container either way so app replacement never risks data.

Open http://localhost:8000, then log in with `admin` / `admin`. You will be forced to set a new password before accessing the app.

> **Production note:** `ALLOWED_HOSTS="*"` is fine for evaluation on a private network. For internet-facing deployments, narrow it to your actual hostname or IP (e.g. `ALLOWED_HOSTS="scanner.example.com,127.0.0.1"`) and set `CSRF_TRUSTED_ORIGINS` if accessing over a domain.

#### Update to latest

```bash
# Single image: pull, then recreate the container (the /data volume persists)
docker pull ghcr.io/cybersecify/openeasd:latest
docker rm -f openeasd      # then re-run the `docker run` command above

# 3-tier compose: the web/worker images are built locally, not pulled
docker compose up -d --build   # the db volume persists all data
```

#### Environment variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | insecure default | Django secret key; **set this in production** |
| `FIELD_ENCRYPTION_KEY` | *(derived from `SECRET_KEY`)* | Optional Fernet key (urlsafe-base64, 32 bytes) encrypting BYOK API keys/webhooks at rest. Set it to decouple secret encryption from `SECRET_KEY` rotation; changing the effective key makes stored secrets unreadable (re-enter them) |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated hostnames (add your server IP/domain) |
| `CSRF_TRUSTED_ORIGINS` | *(none)* | Required if accessing via a domain, e.g. `https://openeasd.example.com` |
| `DEBUG` | `False` | Set `True` only for local development |
| `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | `db` / `5432` / `openeasd` / `openeasd` / — | PostgreSQL connection (or set `DATABASE_URL`) |
| `DBOS_SCAN_CONCURRENCY` | `2` | Max scans executing at once (Postgres has no single-writer lock) |
| `CLOUDFLARE_ACCOUNT_ID` / `CLOUDFLARE_API_TOKEN` | *(none)* | Optional AI analysis (or set in Django admin, AI settings) |
| `SLACK_WEBHOOK_URL` | *(none)* | Slack incoming webhook for scan alerts (can also be set in Django admin, Notification config) |
| `MS_TEAMS_WEBHOOK_URL` | *(none)* | Teams incoming webhook for scan alerts (can also be set in Django admin, Notification config) |
| `ALERT_SEVERITY_THRESHOLD` | `high` | Minimum severity to trigger alerts; overridden by the Notification config in Django admin |
| `SCAN_DAILY_HOUR` | `2` | Hour for daily scheduled scans (24h, in `TIME_ZONE`) |
| `SCAN_DAILY_MINUTE` | `0` | Minute for daily scheduled scans |
| `REPORT_CTA_URL` | *(none)* | Optional URL appended to CSV reports. Renders only when both `REPORT_CTA_URL` and `REPORT_CTA_TEXT` are set |
| `REPORT_CTA_TEXT` | *(none)* | Optional call-to-action line shown alongside `REPORT_CTA_URL` in CSV reports |

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

Three tiers, each its own workload — a default deploy is **3 pods** (logs → stdout, no PVC):

| Workload | Command | Resources |
|---|---|---|
| `openeasd-web` Deployment | init (migrations/admin) → `gunicorn` (2 workers) | 256Mi–512Mi, no `NET_RAW`, Service → :8000 |
| `openeasd-worker` Deployment | `manage.py dbos_worker` | 512Mi–4Gi, `NET_RAW` for nmap/naabu, no Service |
| `openeasd-postgres` StatefulSet | PostgreSQL 17 | 10Gi PVC |

Only the `openeasd-web` Deployment runs migrations (its initContainer); the `openeasd-worker` Deployment waits for them via the role-aware entrypoint (`OPENEASD_ROLE=worker` → `migrate --check`), so there's no DDL race.

> **Scaling:** each Deployment is `replicas: 1` by default. Postgres removes the old single-writer limit, so `openeasd-worker` scales independently — `kubectl scale deploy/openeasd-worker --replicas=N` adds workers all draining the same DBOS queue, without touching the web tier.

#### Health check

`GET /health/` returns `{status, version, git_sha, build_date}`, used by K8s readiness and liveness probes (no auth required).

### Development Mode

```bash
# Starts Django (:8001, serves the UI) + the DBOS worker together
# (needs PostgreSQL running). See the Makefile for the individual commands.
make dev

# UI at http://localhost:8001
```

Full local-dev guide (prerequisites, first-time setup, CI parity,
troubleshooting): [`docs/OPERATIONS.md`](docs/OPERATIONS.md).

## CI/CD

GitHub Actions runs on every push to `main` and `v*` tags:
- **pytest**: fast test suite (~1,730 tests, excludes the 42 slow DNS/RDAP tests in `test_domain_security.py`)
- **bandit**: Python SAST scan
- **pip-audit**: dependency CVE scan
- **Docker build**: amd64 smoke-build on pull requests only
- **Publish to GHCR**: the single image `ghcr.io/cybersecify/openeasd` (`amd64`) published on every `main` push and version tags

## HTTP surface

There is **no REST API** — the UI is a server-rendered plain-Django app (`apps/mvp`,
session auth) served at `/`. The Django-Ninja REST API + JWT Bearer auth were removed
(2026-10-14). The only machine-facing HTTP endpoints are:

- **Report export:** `GET /reports/<scan-uuid>/csv/` (session auth)
- **Health:** `GET /health/` (unauth, for container/K8s probes)
- **Metrics:** `GET /metrics/` (Prometheus, opt-in, off by default)

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

Then add `"apps.my_tool"` to `INSTALLED_APPS` in `openeasd/settings/base.py`. The tool auto-registers in the workflow system.

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
# Fast tests (excludes slow DNS tests, ~1,730 tests)
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py

# All tests (~1,780 total, incl. the 42 slow DNS/RDAP tests)
uv run pytest tests/
```

## Tech Stack

**Backend:**
- **Django 5.2 LTS**: Web framework
- **DBOS**: Durable-execution engine — task queue + scheduler, Postgres-backed (crash-resumable scans)
- **croniter**: Cron parsing for the DBOS user-schedule sweep
- **WhiteNoise**: Serves static files in production (Docker) with gzip compression
- **PostgreSQL** (+ **psycopg 3**): Database — app data and the DBOS checkpoint schema
- **paramiko**: SSH protocol inspection
- **cryptography**: X.509 certificate analysis
- **Django sessions**: login/auth for the server-rendered UI (no JWT, no REST API)

**Frontend:**
- **Bulma + HTMX** (vendored): server-rendered Django templates, no build step, no Node

## License

MIT License - see [LICENSE](LICENSE)

## Author

[Rathnakara GN](https://www.linkedin.com/in/rathnakaragn/) and [Ashok Kamat](https://www.linkedin.com/in/ashokskamat/) / [Cybersecify](https://cybersecify.com)
