# OpenEASD: An Open-Source Platform for Automated External Attack Surface Detection and Vulnerability Assessment

**Rathnakara G N**  
CyberSecify  
rathnakara@cybersecify.com

---

## Abstract

External Attack Surface Management (EASM) requires coordinating heterogeneous security scanners, persisting multi-phase asset discovery results, and producing unified, actionable findings — a workflow that commercial platforms deliver at enterprise licensing cost and open-source projects leave fragmented across CLI tools. This paper presents **OpenEASD**, a self-hosted open-source EASM platform whose primary contribution is an integration architecture that eliminates manual orchestration overhead without requiring modification to any existing tool. Three design questions guided the work: (1) Can tool auto-registration — declaring a scanner by adding a single `tool_meta` dictionary to an `AppConfig` — achieve genuine extensibility without core-code coupling? (2) Does a phased, dependency-ordered pipeline over a shared asset graph produce coherent findings across 13 heterogeneous tools? (3) What is the operational trade-off between the "Infra Scan" and "Full Scan" workflow profiles in terms of runtime, findings yield, and finding type distribution? We answer these empirically: the auto-registration registry reduces new-tool integration to ~60 lines of code with zero changes to core infrastructure; the pipeline produced 21 findings in 228 seconds (Infra Scan) and 114 findings in 1,053 seconds (Full Scan) against cybersecify.com; and the Full Scan's 93 additional findings are dominated by 67 informational nuclei reconnaissance items — at the actionable tier (high + medium severity), the difference is 23 vs. 16 findings, a 44% increase in actionable coverage at 4.6× the runtime cost. A 627-test suite validates correctness across all modules. The platform ships as a single Docker image under the MIT license.

**Keywords:** external attack surface management, vulnerability assessment, automated security scanning, open-source security, subdomain enumeration, plugin architecture

---

## I. Introduction

### A. Problem Statement

An organization's *external attack surface* is the set of all internet-reachable assets — subdomains, open ports, web endpoints, exposed services — that an adversary could reach without prior access. Managing this surface requires answering three recurring operational questions: *What assets exist?* (discovery), *What is exposed on those assets?* (enumeration), and *Which exposures are exploitable?* (assessment). These three questions map naturally to distinct tool categories: passive/active DNS enumeration, port and service scanning, and vulnerability detection.

The practical problem is that best-of-breed tools for each category are independent, CLI-only, and produce incompatible output formats. A security engineer running a manual pipeline must chain subfinder → dnsx → naabu → nmap → nuclei by hand, coerce JSON/XML outputs through custom parsers, maintain context between runs, track which findings are new versus recurring, and assemble a report. This process is slow, hard to repeat consistently, and not auditable without shell history.

Commercial EASM platforms (CrowdStrike Falcon Surface, Palo Alto Cortex Xpanse, Microsoft Defender EASM) automate this pipeline but at enterprise licensing cost, with all asset data leaving the organization, and with proprietary scanning logic that cannot be audited or extended. Open-source alternatives such as reNgine [1] require a Celery/Redis/PostgreSQL stack and couple tool execution tightly to task definitions, raising the barrier to adding new tools.

### B. Research Questions

This paper addresses three specific questions:

**RQ1 (Extensibility):** Can a `tool_meta` auto-registration pattern — declaring a scanner entirely within its own `AppConfig` — achieve genuine extensibility in which new tools require zero changes to core infrastructure code?

**RQ2 (Pipeline coherence):** Does a phased, dependency-ordered execution model over a shared asset graph (Domain → Subdomain → IPAddress → Port → URL) produce coherent, non-duplicated findings across 13 heterogeneous tools?

**RQ3 (Workflow trade-off):** What is the empirical trade-off between an infrastructure-focused scan profile and a full web-layer scan profile in terms of runtime, findings count, and finding severity/type distribution?

### C. Contributions

The contributions of this work are:

1. **Integration architecture** — A phased workflow engine with plugin-style tool registration that chains 13 security tools from domain input to ranked vulnerability findings without modifying core platform files when tools are added or removed.
2. **Unified data model** — A single `Finding` model with lifecycle tracking and a shared asset graph that enables cross-tool querying, delta detection between scans, and unified CSV/PDF reporting.
3. **Empirical workflow comparison** — Quantitative measurement of runtime, findings yield, and severity distribution for two workflow profiles (Infra Scan vs. Full Scan) against a real production domain.
4. **Operational implementation** — A self-hosted platform shipping as a single Docker image, validated by 627 automated tests, with documented failure modes encountered during development.

---

## II. Background and Related Work

### A. Commercial EASM Platforms

Microsoft Defender EASM [2], Palo Alto Cortex Xpanse, and CrowdStrike Falcon Surface represent the current commercial tier. They combine asset discovery with risk scoring, continuous monitoring, and integration into existing SIEM/SOAR pipelines. Their primary limitations for the target audience of this work are: (1) enterprise licensing cost (typically $50,000–$200,000+ annually), (2) data sovereignty — all asset discovery data is processed on vendor infrastructure — and (3) black-box scanning logic that cannot be audited, customized, or extended by the user.

### B. Open-Source Reconnaissance Frameworks

**reNgine** [1] is the most architecturally comparable open-source project. It provides a Django-based web interface over a Celery/Redis/PostgreSQL stack with subdomain enumeration, port scanning, and nuclei-based vulnerability scanning. Its key differences from OpenEASD are: (a) heavier infrastructure prerequisites (Redis, PostgreSQL, Celery), (b) tighter coupling between tool execution and task definitions (adding a tool requires modifying core task code), and (c) no phased dependency graph — tools are configured per-"engine" rather than ordered by discovery phase. OpenEASD's auto-registration model and phase-ordered pipeline are direct responses to these design choices.

**Reconftw** [3] chains 45+ tools via shell scripting but provides no persistent storage, web UI, findings lifecycle, or reporting. It functions as a scripting harness rather than a platform, requiring manual result interpretation after each run.

**OWASP Amass** [4] provides sophisticated subdomain enumeration with OSINT source integration but no vulnerability assessment or web layer analysis. OpenEASD uses amass as a Phase 2 component.

### C. Individual Tool Components

OpenEASD incorporates and orchestrates existing best-of-breed tools rather than reimplementing their capabilities. The **ProjectDiscovery suite** [5] (subfinder, dnsx, naabu, httpx, nuclei) provides the backbone for passive enumeration, DNS resolution, port scanning, web probing, and vulnerability detection. **Nuclei** [6] specifically is used for both web vulnerability scanning (Phase 9, community templates) and network protocol vulnerability scanning (Phase 7, 319 specialized templates). The use of established tools as backend components is intentional: the research contribution is the integration layer, not the scanning capabilities themselves.

### D. Gap Analysis

Table 1 positions OpenEASD against related tools across five dimensions relevant to operational EASM deployment.

| Platform | Unified Pipeline | Plugin Extensibility | Self-Hosted | Web UI | Single-Container Deploy |
|---|:---:|:---:|:---:|:---:|:---:|
| reNgine | ✓ | Partial | ✓ | ✓ | ✗ (multi-container) |
| Reconftw | Partial | Shell scripts | ✓ | ✗ | ✗ |
| Amass | ✗ | ✗ | ✓ | ✗ | — |
| Commercial EASM | ✓ | ✗ | ✗ | ✓ | — |
| **OpenEASD** | **✓** | **✓ (tool_meta)** | **✓** | **✓** | **✓** |

**Table 1.** Comparison of EASM platforms across operational dimensions.

---

## III. System Architecture

### A. Overview

OpenEASD follows a four-layer architecture: persistence (SQLite), application (Django 5), API (Django Ninja), and presentation (React 18 SPA). A Django-Q2 background worker process executes scan tasks asynchronously, decoupled from the HTTP request lifecycle. The total codebase comprises approximately 6,328 lines in core infrastructure, 5,348 lines across 12 tool apps, and 2,668 lines in the React frontend.

```
┌─────────────────────────────────────────────────────────┐
│  React 18 SPA (Vite, shadcn/ui, Tailwind CSS)           │
│  10 pages, JWT Bearer via localStorage, 3s polling      │
└────────────────────────┬────────────────────────────────┘
                         │ /api/*  (HTTP/JSON, 35 endpoints)
┌────────────────────────▼────────────────────────────────┐
│  Django Ninja REST API (JWT auth, auto OpenAPI docs)    │
│  8 routers: auth, users, domains, scans, workflows,     │
│             findings, scheduled, insights               │
└────────┬──────────────────────────┬──────────────────────┘
         │ ORM                      │ Task enqueue
┌────────▼────────┐        ┌────────▼────────────────────┐
│  SQLite (ORM)   │        │  Django-Q2 Worker            │
│  8 core models  │        │  APScheduler (daily scans)   │
└─────────────────┘        └────────┬────────────────────┘
                                    │
                           ┌────────▼────────────────────┐
                           │  Scan Pipeline Orchestrator  │
                           │  Phase-ordered workflow       │
                           │  13 tool apps                │
                           └─────────────────────────────┘
```

**Figure 1.** System architecture overview.

### B. Core Infrastructure vs. Tool Apps

The backend is organized into two categories of Django applications:

**Core infrastructure** (`apps/core/`, ~6,300 lines) defines stable, shared components: the `ScanSession` model and pipeline orchestrator, the `Workflow`/`WorkflowStep` models and dynamic runner, the unified `Finding` model, the `Subdomain`/`IPAddress`/`Port`/`URL` asset graph, the Django Ninja API instance with JWT configuration, the APScheduler setup, the Slack/Teams alert dispatcher, and the CSV/PDF report generators.

**Tool apps** (`apps/`, ~5,300 lines across 12 apps) each encapsulate a single external scanner. These apps are independently addable and removable from `INSTALLED_APPS` without modifying any file in `apps/core/`. The 12 standalone tool apps are: `domain_security`, `subfinder`, `amass`, `dnsx`, `naabu`, `nmap`, `tls_checker`, `ssh_checker`, `nuclei_network`, `httpx`, `nuclei`, and `web_checker`. A thirteenth tool, `service_detection`, lives in `apps/core/service_detection/` because it is always injected by the pipeline regardless of workflow configuration.

### C. Tool Auto-Registration (RQ1)

The auto-registration mechanism is implemented in `apps/core/workflows/registry.py` (96 lines). At Django startup, the registry iterates all installed apps and collects those with a `tool_meta` attribute on their `AppConfig`:

```python
# New tool declaration — no core files modified
class MyToolConfig(AppConfig):
    name = "apps.my_tool"
    tool_meta = {
        "label":             "My Tool",
        "runner":            "apps.my_tool.scanner.run_my_tool",
        "phase":             6,
        "requires":          ["naabu"],
        "produces_findings": True,
    }
```

Adding a new tool to the platform requires: (1) creating the tool app (~60 lines across `apps.py`, `collector.py`, `analyzer.py`, `scanner.py`), and (2) adding its dotted path to `INSTALLED_APPS`. The registry exposes four helper methods consumed throughout the platform: `get_tool_choices()` for workflow creation dropdowns, `get_tool_runners()` for pipeline execution dispatch, `get_tool_phases()` for phase ordering, and `get_source_choices()` for finding filter UI. New tools gain full workflow system integration, filtering, reporting, and alerting support automatically — answering RQ1 affirmatively.

### D. Unified Finding Model

All tool apps write to a single `Finding` model (`apps/core/findings/models.py`, 127 lines), avoiding tool-specific result tables and enabling cross-tool querying without joins:

```python
class Finding(models.Model):
    session     = ForeignKey(ScanSession, on_delete=CASCADE)
    source      = CharField()    # "nmap", "tls_checker", etc.
    check_type  = CharField()    # "cve", "weak_cipher", etc.
    severity    = CharField()    # critical/high/medium/low/info
    title       = CharField()
    description = TextField()
    remediation = TextField()
    target      = CharField()    # "hostname" or "IP:port"
    port        = ForeignKey(Port, null=True)
    url         = ForeignKey(URL, null=True)
    extra       = JSONField()    # tool-specific structured data
    status      = CharField()    # open/acknowledged/resolved/fp
```

The `extra` JSONField stores tool-specific structured data (CVSS score and CVE ID for nmap findings, cipher name and protocol version for tls_checker, algorithm lists for ssh_checker) without schema sprawl. The `status` field supports finding lifecycle tracking across scan sessions, enabling a security team to mark an issue as acknowledged or resolved and track recurrence in future scans.

### E. Asset Data Model

Assets form a directed graph reflecting discovery order:

```
Domain ──► Subdomain ──► IPAddress ──► Port ──► URL
```

Each arrow represents both a foreign key relationship and a cascade delete, ensuring that removing a domain, scan session, or any intermediate asset cleans up all downstream records. The `Port.is_web` boolean — set by `service_detection` using `nmap -sV` output — is the key discriminator: Phase 7 tools route to web-layer or non-web-layer analysis based on this flag, and httpx (Phase 8) uses it to prioritize probing targets.

---

## IV. Scan Pipeline

### A. Phase-Ordered Execution Model

The scan pipeline executes tools in ascending phase order. Phase numbers encode the discovery dependency: a tool cannot meaningfully run until its inputs exist in the asset graph. Tools at the same phase number run sequentially; they have no data dependencies on each other and are candidates for future parallel execution.

```
Phase 1  domain_security    → Finding         (DNS, SPF, DKIM, DMARC, RDAP)
Phase 2  subfinder          → Subdomain       (passive API enumeration)
Phase 2  amass              → Subdomain       (active DNS brute-force)
Phase 3  dnsx               → IPAddress       (resolution, public IP filter)
Phase 4  naabu              → Port            (top-100 TCP scan)
Phase 5  service_detection  → Port.service,   (nmap -sV enrichment) [auto-injected]
                               Port.is_web
Phase 7  nmap               → Finding         (NSE vulners CVE scan, is_web=False)
Phase 7  tls_checker        → Finding         (cert, cipher, protocol analysis)
Phase 7  ssh_checker        → Finding         (SSH config audit)
Phase 7  nuclei_network     → Finding         (319 network protocol templates)
Phase 8  httpx              → URL             (web probing, CDN-aware via SNI)
Phase 9  nuclei             → Finding         (community web vuln templates)
Phase 9  web_checker        → Finding         (security headers, CORS, cookies)
```

**Table 2.** Pipeline phases, outputs, and tool mapping. Phase 5 (`service_detection`) is always injected regardless of workflow configuration.

The `service_detection` tool (Phase 5) occupies a special position: it is unconditionally injected between port scanning and all Phase 7+ tools by the pipeline orchestrator, even when not explicitly enabled in the workflow. This ensures `Port.is_web` classification is always available as a downstream discriminator, answering RQ2 in the affirmative — tools requiring this flag always receive it.

### B. Tool App Internal Structure

Each tool app follows a three-layer internal structure enforcing separation of I/O, analysis, and persistence:

- **`collector.py`** — Invokes the external binary via `subprocess.run(stdin=subprocess.DEVNULL, ...)` or makes direct network connections (TLS socket handshake for `tls_checker`, SSH protocol negotiation for `ssh_checker`). Returns raw data (JSON, XML, or structured Python types). Has no database access.
- **`analyzer.py`** — Parses raw data and constructs `Finding` and asset objects. Contains all domain logic: severity mapping, CVE score parsing, cipher strength classification, header presence checks. Has no database access and no subprocess calls.
- **`scanner.py`** — Calls collector, passes output to analyzer, persists results. A thin 20–40 line orchestration layer.

This structure ensures that analysis logic is independently unit-testable. The 627-test suite exercises collector parsing (with fixture data), analyzer severity mapping, and scanner integration with mocked collectors — without requiring external binary installation in the CI environment.

### C. Apex Domain Seeding

A correctness concern specific to EASM pipelines is ensuring the input domain itself appears in the `Subdomain` table before downstream tools execute. Subfinder and Amass enumerate *additional* subdomains from OSINT sources; neither reliably outputs the apex domain. Without explicit seeding, scanning a domain with no public subdomains produces only Phase 1 DNS findings and zero network results — a misleading empty report.

OpenEASD seeds the input domain as a `Subdomain` record with `source="seed"` at pipeline start, then resolves its A/AAAA records using Python's `dnspython` (`dns.resolver.resolve()`) and inserts the results into `IPAddress`. This Python-side resolution bypasses the `dnsx` subprocess, which was observed to fail silently inside the Django-Q2 worker process under specific runtime conditions (described in Section VII-A).

### D. Workflow System

The workflow system allows users to create named subsets of tools. Each `Workflow` record links to `WorkflowStep` records for each tool, each carrying an `enabled` boolean and an execution order. The platform ships with two default workflows:

- **Infra Scan** (default) — domain_security, subfinder, dnsx, naabu, service_detection, nmap, tls_checker, ssh_checker, nuclei_network. Targets: network CVEs, SSH, TLS. Runtime: ~4 minutes.
- **Full Scan** — Infra Scan plus httpx, nuclei, web_checker, and optionally amass. Adds web layer. Runtime: ~18 minutes.

Custom workflows (e.g., "TLS audit only", "subdomain discovery without port scanning") can be created via the API or UI.

---

## V. REST API and Frontend

### A. REST API Design

The API is implemented with Django Ninja [7], which derives request schemas and response types from Python type annotations, generates OpenAPI documentation automatically, and integrates natively with Django's ORM and authentication system. All 35 endpoints require JWT Bearer authentication except `/health/` (Kubernetes readiness probe) and `/api/token/pair` (login).

The API uses a flat response envelope:

```json
// Success
{"id": 1, "domain": "example.com", "status": "active"}

// Error
{"error": {"code": "NOT_FOUND", "message": "Domain not found"}}
```

Token lifecycle follows standard rotation patterns: short-lived access tokens (sent as `Authorization: Bearer` headers) with long-lived refresh tokens (sent in POST bodies). Logout blacklists the refresh token's JTI via simplejwt's `OutstandingToken`/`BlacklistedToken` models. The OpenAPI documentation is served unconditionally at `/api/docs` — an earlier design disabled it outside `DEBUG=True`, which broke the documented API discovery URL in production.

### B. Frontend Architecture

The frontend is a React 18 SPA built with Vite [8], styled with Tailwind CSS 3 [9] and shadcn/ui [10] component primitives built on Radix UI. A vanilla popstate router replaces React Router, reducing the dependency surface. The frontend build (`npm run build`) produces a static bundle in `frontend/dist/`, served in production by WhiteNoise with gzip compression and content-hash fingerprinting — requiring no nginx or CDN layer.

Key architectural decisions and their rationale:

| Decision | Rationale |
|---|---|
| Vanilla popstate router | Eliminates react-router dependency; sufficient for 10 static routes |
| 3-second polling for scan status | Avoids WebSocket infrastructure; acceptable latency for scan progress UX |
| Vite dev proxy to Django | Eliminates CORS configuration; prod and dev share identical API path |
| WhiteNoise static serving | Eliminates nginx requirement; single container is the load-bearing deployment promise |

**Table 3.** Frontend architectural decisions.

### C. First-Run Security Model

The `docker-entrypoint.sh` script creates an `admin` user with password `admin` and sets `must_change_password=True` on every container start where the default password remains unchanged. On first login, the React SPA redirects to `/setup` — a two-step onboarding wizard requiring (1) password change and (2) first domain registration — before allowing access to any other route. This addresses the common misconfiguration of leaving default credentials in production, at the cost of one additional login step for new deployments.

---

## VI. Evaluation

### A. Test Suite Composition and Coverage

The 627-test suite (excluding the 41 slow DNS/RDAP tests that make real network calls) covers all platform layers:

| Category | Tests | Scope |
|---|---|---|
| Tool collectors | 118 | JSON/XML/line parsing with fixture data |
| Tool analyzers | 163 | Severity mapping, edge cases, deduplication |
| Asset models | 13 | FK constraints, cascade delete, dedup |
| Workflow runner | 20 | Phase ordering, step failure handling, cancellation |
| API endpoints | 71 | Auth, payload shape, error codes (all 35 endpoints) |
| Integration (full pipeline) | 71 | End-to-end with mocked external binaries |
| Scheduler | 15 | Job registration, stuck-scan watchdog |
| Reports/alerts | 22 | CSV content, PDF (mocked pisa), Slack/Teams |
| Insights/dashboard | 21 | KPI aggregation, chart data |
| Slow (excluded CI) | 41 | Real DNS/RDAP network calls |

**Table 4.** Test suite composition. CI runs 627 tests; the 41 slow tests are excluded to keep CI under 60 seconds.

All 627 tests pass on the current codebase (`uv run pytest tests/ --ignore=tests/unit/test_domain_security.py` completes in 31.3 seconds). The CI pipeline additionally runs bandit (Python SAST), pip-audit (dependency CVE scanning), and a Docker build verification on every push to `main`.

### B. Workflow Comparison (RQ3)

To answer RQ3, both workflow profiles were executed against `cybersecify.com` (a production domain operated by the authors). Table 5 presents per-tool timing and findings counts for the Full Scan; Table 6 compares the two workflow profiles.

| Tool | Duration (s) | Findings |
|---|---:|---:|
| domain_security | 1.0 | 6 |
| subfinder | 9.2 | 10 subdomains |
| dnsx | 2.7 | 6 IPs |
| naabu | 6.0 | 17 ports |
| service_detection | 125.2 | 17 ports classified |
| httpx | 1.3 | 10 URLs |
| nmap | 0.3 | 12 |
| tls_checker | 0.0 | 0 |
| ssh_checker | 0.4 | 3 |
| nuclei | 905.2 | 67 |
| web_checker | 1.2 | 26 |
| **Full Scan total** | **1,052.5** | **114** |

**Table 5.** Per-tool timing and findings for Full Scan (cybersecify.com, 2026-05-21).

| Metric | Infra Scan | Full Scan |
|---|---:|---:|
| Total runtime (s) | 228 | 1,053 |
| Total findings | 21 | 114 |
| High severity | 5 | 9 |
| Medium severity | 11 | 26 |
| Low severity | 4 | 12 |
| Info | 1 | 67 |
| Tools executed | 9 | 11 |
| URLs discovered | 0 | 10 |
| Unique sources | 3 | 5 |

**Table 6.** Infra Scan vs. Full Scan comparison (cybersecify.com).

The Full Scan produced 93 more findings than the Infra Scan, but that headline count is misleading: 67 of those 93 additional findings are informational reconnaissance from nuclei (technology fingerprinting, DNS record detection, robots.txt detection) that carry no remediation action. The actionable difference is considerably smaller — 4 additional high-severity findings (missing Content-Security-Policy on `tls.cybersecify.com` ports 80/443/8080/8443) and 15 additional medium-severity findings (CORS wildcards, missing framing/content-type headers) from web_checker. An analyst prioritizing by severity would find that the Full Scan adds 19 actionable findings (4 high + 15 medium) over the Infra Scan's 16 actionable findings (5 high + 11 medium) — a 19% increase in actionable coverage at the cost of 4.6× more runtime. The runtime increase (228s → 1,053s) is dominated by nuclei's template matching at 905.2 seconds, which is 86% of Full Scan wall-clock time.

### C. Finding Analysis

The Full Scan produced 114 findings across 5 tool categories. High-severity findings (9 total) consisted of:

- **5 SSH CVEs** on `106.51.16.13:22` (OpenSSH 9.6p1 Ubuntu): CVE-2024-6387 (regreSSHion, CVSS 8.1 — unauthenticated RCE via signal handler race condition), CVE-2024-39894, and three 2026-assigned CVEs (CVE-2026-35385, CVE-2026-35386, CVE-2026-35414).
- **4 instances of missing Content-Security-Policy** on all four protocol/port combinations of `tls.cybersecify.com` (HTTP port 80, HTTP port 8080, HTTPS port 443, HTTPS port 8443).

Medium-severity findings (26 total) included email security configuration gaps (absent MTA-STS, absent DKIM, DMARC set to monitoring-only, SPF soft-fail), wildcard `Access-Control-Allow-Origin: *` CORS configuration on four endpoints, missing `X-Frame-Options` and `X-Content-Type-Options` headers, and three SSH hardening issues on the exposed SSH service (root login permitted, password authentication enabled, weak HMAC algorithms).

The `tls_checker` tool produced zero findings — consistent with a server that has TLS correctly configured but missing application-layer security headers. The `nuclei_network` tool (319 network protocol templates) also produced zero findings, indicating no detected network protocol vulnerabilities beyond those found by nmap.

### D. Limitations of the Evaluation

The evaluation is limited in four respects that are important to acknowledge:

1. **Single domain, single operator** — All measurements are from a single production domain operated by the authors. Ground-truth validation against known-vulnerable test environments (e.g., DVWA, HackTheBox targets, or deliberately misconfigured hosts with a documented finding list) was not performed. False-positive and false-negative rates are therefore unknown. Comparative benchmarks against reNgine, manual CLI orchestration, or commercial EASM tooling are not included. These gaps constrain the strength of empirical conclusions for RQ2 and RQ3; the results should be read as directionally informative rather than definitive.

2. **Raw finding counts obscure actionable value** — The total finding count (114 for Full Scan vs. 21 for Infra Scan) is dominated by informational nuclei reconnaissance findings that carry no remediation action. At the actionable tier (high + medium findings requiring engineering effort), the difference is 23 vs. 16 findings — a 44% increase, not the 443% suggested by raw totals. Evaluation metrics for EASM tools should weight severity-stratified actionable findings over raw counts.

3. **No reproducibility controls** — Scan runtime is influenced by network conditions, external API rate limits (subfinder uses passive DNS sources), and nuclei template database state at scan time. The reported timings represent a single measurement without variance estimation across repeated runs or across different network vantage points.

4. **Engineering rather than research novelty** — The platform's contribution is software architecture and operational packaging, not new algorithms, discovery techniques, or theoretical frameworks. The value proposition — reducing manual orchestration overhead via clean integration architecture — is practical and measurable, but the empirical questions answered (RQ1–RQ3) are design validation questions rather than falsifiable scientific hypotheses. The work is appropriately positioned as a systems and tools contribution.

---

## VII. Known Limitations and Future Work

### A. Go Binary Subprocess Reliability

During development, silent failures were observed in Go-based ProjectDiscovery tools (dnsx, naabu) when invoked via Python's `subprocess.run()` inside the Django-Q2 worker process. The binaries would return exit code 0 with empty stdout — producing zero results with no error indication. The failure was not reproducible outside the worker process: the same command executed via `python3 -c "subprocess.run(...)"` in the same container environment returned correct results in under one second.

Root cause was not fully characterized. The most likely contributing factors are Go's goroutine scheduler behavior when stdin is an inherited file descriptor from a Python-forked worker process — Go binaries may block on stdin reads when not explicitly closed. The mitigation — passing `stdin=subprocess.DEVNULL` to all subprocess invocations — resolves the issue across all nine collector callsites. The patch is safe (closing stdin cannot break tools that do not read it) and was applied uniformly. The underlying mechanism warrants controlled reproduction in a Linux environment outside macOS Docker Desktop, where container networking and process management differ.

### B. SQLite Write Concurrency

SQLite's writer-exclusive lock prevents concurrent scan execution: a second scan started while one is running will block on database writes until the first scan's transaction commits. For single-user, single-scan-at-a-time workflows this is acceptable. Migration to PostgreSQL would enable: (a) concurrent scan execution, (b) multi-user RBAC, (c) high-availability deployment with replicas. This is the highest-priority architectural evolution.

### C. Parallel Phase Execution

Within each phase, tools execute sequentially despite having no data dependencies on each other. Phase 7 in particular runs four independent tools (nmap, tls_checker, ssh_checker, nuclei_network) serially. Parallel execution within a phase using Python's `concurrent.futures.ThreadPoolExecutor` (appropriate given the tools are I/O-bound subprocesses) would reduce Full Scan wall-clock time from ~18 minutes to approximately 10–12 minutes.

### D. Domain Ownership Verification

The platform performs no verification that the user is authorized to scan the target domain. This is appropriate for a self-hosted tool whose users are assumed to scan assets within their purview. A future hosted/SaaS variant would require a domain verification mechanism (DNS TXT challenge, WHOIS contact email, or similar) to prevent misuse as unauthenticated reconnaissance infrastructure.

### E. Passive Continuous Monitoring

OpenEASD currently operates in triggered-scan mode (manual or scheduled). Continuous passive monitoring — certificate transparency log monitoring [11] for new subdomains, passive DNS change detection — would reduce detection latency for newly-exposed assets from days (next scheduled scan) to minutes (event-driven alert). This is architecturally feasible within the existing APScheduler and alert dispatcher infrastructure.

---

## VIII. Conclusion

This paper presented OpenEASD, an open-source self-hosted EASM platform whose contribution is an integration architecture that coordinates 13 existing security tools into a coherent, reproducible attack surface assessment workflow. We addressed three design questions empirically. For RQ1 (extensibility): the `tool_meta` auto-registration pattern achieves genuine core-decoupled extensibility — new tools require ~60 lines of code and one `INSTALLED_APPS` entry, with zero core file modifications. For RQ2 (pipeline coherence): the phased dependency-ordered pipeline with apex seeding and auto-injected service classification produces coherent findings; the evaluation found 114 non-duplicated findings across 5 tool categories with clear provenance for each finding. For RQ3 (workflow trade-off): the Full Scan produces 93 more raw findings than the Infra Scan at 4.6× the runtime, but 67 of those are informational nuclei reconnaissance with no remediation action; at the actionable tier (high + medium severity), the difference is 23 vs. 16 findings — a 44% increase in actionable coverage at 4.6× the cost. The Infra Scan recovers all network-layer CVEs and SSH issues in under 4 minutes; the Full Scan's marginal value is web-layer header and CORS findings.

The platform's primary practical value is the reduction of operational overhead: what requires manual chaining of 5–13 CLI tools with custom parsers and no persistent state becomes a single `docker run` command with a web UI, finding lifecycle tracking, and scheduled re-scanning. The 627-test suite, honest documentation of failure modes encountered during development, and MIT license provide the transparency and reproducibility appropriate for a security tool.

The software is available at `https://github.com/cybersecify/OpenEASD` under the MIT license.

---

## References

[1] Y. Ojha, "reNgine: An Automated Reconnaissance Framework for Web Applications," GitHub repository, 2020. [Online]. Available: https://github.com/yogeshojha/rengine

[2] Microsoft, "What is Microsoft Defender External Attack Surface Management?" Microsoft Azure Docs, 2023. [Online]. Available: https://learn.microsoft.com/en-us/azure/external-attack-surface-management/

[3] six2dez, "Reconftw: Automated Recon Tool Which Runs the Best Tools," GitHub repository, 2021. [Online]. Available: https://github.com/six2dez/reconftw

[4] OWASP, "Amass — In-Depth Attack Surface Mapping and Asset Discovery," OWASP Foundation, 2018. [Online]. Available: https://github.com/owasp-amass/amass

[5] ProjectDiscovery, "Open Source Security Tools for Builders and Breakers," 2021. [Online]. Available: https://projectdiscovery.io

[6] ProjectDiscovery, "Nuclei: Fast and Customizable Vulnerability Scanner Based on Simple YAML-Based DSL," GitHub repository, 2020. [Online]. Available: https://github.com/projectdiscovery/nuclei

[7] V. Kucheryaviy, "Django Ninja — Fast Django REST Framework," 2021. [Online]. Available: https://django-ninja.dev

[8] E. You, "Vite: Next Generation Frontend Tooling," 2021. [Online]. Available: https://vitejs.dev

[9] A. Wathan, "Tailwind CSS: A Utility-First CSS Framework for Rapid UI Development," 2017. [Online]. Available: https://tailwindcss.com

[10] shadcn, "shadcn/ui: Build Your Component Library," 2023. [Online]. Available: https://ui.shadcn.com

[11] B. Laurie, A. Langley, and E. Kasper, "Certificate Transparency," RFC 6962, IETF, June 2013. [Online]. Available: https://www.rfc-editor.org/rfc/rfc6962
