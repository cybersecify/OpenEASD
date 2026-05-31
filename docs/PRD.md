# OpenEASD — Product Requirements Document

> **Audience:** product / PM view. For architecture see [DESIGN.md](DESIGN.md).
> For engineering decisions see [DECISIONS.md](DECISIONS.md).

---

## What

OpenEASD (Open External Attack Surface Detection) is a self-hosted platform
that scans a set of domains and surfaces their external attack surface:
subdomains, open ports, TLS weaknesses, CVEs, web vulnerabilities, SSH
misconfigurations, DNS/email security gaps, and HTTP header issues.

Users point it at their domains, click Scan, and receive a structured,
exportable report — without needing to orchestrate subfinder, naabu, nuclei,
nmap, and friends by hand.

---

## Who

**Primary audience:** the security community — people who already know what
nuclei, subfinder, and nmap are and prefer a GUI over manual CLI orchestration.

| User type | Fit |
|---|---|
| In-house security engineers | Core use case — own-domain continuous monitoring |
| IT engineers handed security responsibility | Core use case — don't want to learn every tool separately |
| Small security consultancies | Core use case — repeatable scans across client domains |
| Security learners | Strong fit — GUI makes the toolchain visible and approachable |
| Bug bounty hunters / elite red-teamers | Weak fit — prefer raw CLI speed |
| Enterprise SOCs | Out of scope — no RBAC, SAML, HA, or Postgres |
| Non-technical end users | Out of scope — Workflows page and tool labels assume security literacy |

See [D-001](DECISIONS.md#d-001--audience-security-literate-users-not-non-technical-end-users).

---

## Why

The ProjectDiscovery toolchain (subfinder, dnsx, naabu, httpx, nuclei) and
adjacent tools (nmap, amass) are individually excellent but require
per-tool knowledge, manual chaining, and result aggregation. OpenEASD
provides the orchestration layer and a unified findings surface so security
engineers spend time on findings, not on pipeline plumbing.

---

## Where / Distribution

- **Delivery:** `ghcr.io/cybersecify/openeasd:latest` (Docker) and `k8s/`
  Kubernetes manifests. One `docker run` command is the load-bearing install
  experience.
- **No hosted scan UI.** Domain-ownership verification for a public scanner
  is a hard prerequisite; it isn't built yet.
  See [D-003](DECISIONS.md#d-003--distribution-docker-only).
- **License:** MIT. Chosen deliberately to match the security community's
  expectation of genuine open source.
  See [D-002](DECISIONS.md#d-002--license-mit-not-sul-or-fair-code).

---

## What It Does — 11 Attack Vectors

These are the customer-facing attack vectors in canonical order
(see [D-007](DECISIONS.md#d-007--canonical-11-attack-vectors-customer-facing)):

| # | Vector | Tools |
|---|---|---|
| 1 | Subdomain Discovery | subfinder (passive), amass (active) |
| 2 | Open Ports | naabu (top-100 TCP) |
| 3 | DNS Security | domain_security — DNSSEC, CAA, AXFR, wildcard, lame-delegation |
| 4 | Email Security | domain_security — SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI |
| 5 | TLS / SSL | tls_checker — cipher suites, protocol versions, cert expiry, HSTS |
| 6 | SSH Configuration | ssh_checker — root login, weak kex/cipher/MAC, SSHv1 |
| 7 | CVE Detection | nmap NSE vulners + service-aware nuclei network templates (non-web ports) |
| 8 | Domain Registration Health | domain_security — RDAP expiry, registrar, WHOIS |
| 9 | Web Probing & URL Discovery | httpx — CDN-aware via SNI, URL seeding |
| 10 | Web Vulnerability Scanning | nuclei community templates (web URLs) |
| 11 | HTTP Security Headers / Cookies / CORS | web_checker |

---

## Key Constraints

| Constraint | Value |
|---|---|
| Auth | Single admin user, JWT (no RBAC, no SAML) |
| Database | SQLite (configurable via `DB_NAME`; Postgres not supported) |
| Concurrency | `replicas: 1` — SQLite RWO |
| Background tasks | Django-Q2 (ORM broker, no Redis/Celery) |
| External binaries | subfinder, dnsx, naabu, httpx, nuclei, nmap, amass — must be present on PATH or via `TOOL_*` env vars |
| Capabilities | `NET_RAW` required on the worker container for nmap raw socket scanning |

---

## What It Deliberately Does Not Do

See [D-008](DECISIONS.md#d-008--things-we-deliberately-dont-have-anti-features)
for the full rationale.

- No RBAC, SAML, or multi-tenant support
- No Postgres or horizontal scaling
- No hosted "scan any domain" UI
- No A–F grades, typosquatting, leaked credentials, brand impersonation,
  technology fingerprinting — those belong to a separate product
- No "AI-powered" features in marketing copy

---

## Success Criteria

A successful install meets all of these:

1. `docker run` completes without error; UI loads at `:8000`
2. First scan against a real domain returns subdomains, open ports, and at
   least one finding within the expected tool runtime
3. PDF and CSV export buttons produce valid downloads
4. Continuous monitoring rescans a domain on the configured interval
5. Slack / Teams alerts fire when new findings exceed the severity threshold
