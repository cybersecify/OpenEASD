# OpenEASD — Product Requirements Document

> **Audience:** product / PM view. This is the first doc in the design flow;
> next is the domain model ([02-domain.md](02-domain.md)), then architecture ([03-system.md](03-system.md)).
> For engineering decisions see [DECISIONS.md](DECISIONS.md); full index + reading
> order in [CLAUDE.md](../CLAUDE.md).

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
| Enterprise SOCs | Out of scope — no RBAC, SAML, or HA |
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

- **Delivery:** `ghcr.io/cybersecify/openeasd-web` + `ghcr.io/cybersecify/openeasd-worker`
  (Docker, published `:latest` and `:vX.Y.Z`) run via `docker compose` alongside
  PostgreSQL, plus `k8s/` Kubernetes manifests. `docker compose up -d` is the
  load-bearing install experience.
- **No hosted scan UI.** Domain-ownership verification for a public scanner
  is a hard prerequisite; it isn't built yet.
  See [D-003](DECISIONS.md#d-003--distribution-docker-only).
- **License:** MIT. Chosen deliberately to match the security community's
  expectation of genuine open source.
  See [D-002](DECISIONS.md#d-002--license-mit-not-sul-or-fair-code).

---

## What It Does — 16 Attack Vectors

These are the customer-facing attack vectors in canonical order
(see [D-007](DECISIONS.md#d-007--canonical-attack-vectors-customer-facing)).
This is the product view — what each vector *surfaces*, in plain terms. The
tools behind each one live in the system + technical docs
([03-system.md](03-system.md), [CLAUDE.md](../CLAUDE.md) pipeline), not here.

| # | Attack Vector | What it surfaces |
|---|---|---|
| 1 | Subdomain Discovery | The full set of subdomains exposed to the internet |
| 2 | Open Ports & Services | Which network ports and services are reachable |
| 3 | DNS Security | Weaknesses and misconfigurations in DNS |
| 4 | Email Security | Gaps in email anti-spoofing and delivery protection |
| 5 | TLS / SSL | Weak encryption, expiring or misconfigured certificates |
| 6 | SSH Configuration | Insecure remote-access settings |
| 7 | CVE Detection | Known vulnerabilities in exposed software, prioritized by real-world exploitability |
| 8 | Domain Registration Health | Expiry, ownership and registrar risk |
| 9 | Web Probing & URL Discovery | The live web footprint and reachable pages |
| 10 | Web Vulnerability Scanning | Exploitable flaws in web applications |
| 11 | HTTP Security Headers, Cookies & CORS | Missing browser-side protections |
| 12 | Brand Threat | Lookalike and cybersquatting domains impersonating the brand |
| 13 | Credential & Breach Exposure | Company credentials leaked in breaches and infostealer logs |
| 14 | Leaked Secrets | API keys and secrets exposed in public code and web assets |
| 15 | Cloud & Takeover Exposure | Open cloud storage and hijackable dangling assets |
| 16 | External Asset Intelligence | Owned IP ranges and infrastructure referenced in public sources |

---

## Key Constraints

| Constraint | Value |
|---|---|
| Auth | Single admin user, JWT (no RBAC, no SAML) |
| Database | **PostgreSQL** (via `DB_*` env or `DATABASE_URL`) — holds app data **and** the DBOS checkpoint schema |
| Concurrency | The worker scales independently (Postgres has no single-writer lock); `DBOS_SCAN_CONCURRENCY` caps parallel scans |
| Background tasks | **DBOS** durable workflows (checkpoint/resume) + `@scheduled` crons — no Django-Q/Celery/Redis |
| External binaries | subfinder, dnsx, naabu, httpx, nuclei, nmap, amass (+ the passive-tool CLIs) — on PATH or via `TOOL_*` env vars |
| Capabilities | `NET_RAW` required on the worker container for nmap raw socket scanning |

---

## What It Deliberately Does Not Do

See [D-008](DECISIONS.md#d-008--things-we-deliberately-dont-have-anti-features)
for the full rationale.

- No RBAC, SAML, or multi-tenant support (single-user by design)
- No hosted "scan any domain" UI — domain-ownership verification for a public
  scanner isn't built
- No deep brand-impersonation / dark-web *monitoring* — out of scope by focus.
  The boundary is continuous brand/dark-web *monitoring*, not the point-in-time,
  surface-adjacent signals that ship as scan vectors: Brand Threat (vector 12 —
  passive lookalike/cybersquatting detection), Credential & Breach Exposure
  (vector 13 — aggregate breach/infostealer counts, never plaintext credentials),
  and a per-scan Exposure Score with an A–F grade were all added since the
  original PRD
- No "AI-powered" marketing copy — the optional AI analysis layer (BYOK,
  off by default) is described by what it does, never as "AI-powered" (D-008)

---

## Success Criteria

A successful install meets all of these:

1. `docker run` completes without error; UI loads at `:8000`
2. First scan against a real domain returns subdomains, open ports, and at
   least one finding within the expected tool runtime
3. PDF and CSV export buttons produce valid downloads
4. Continuous monitoring rescans a domain on the configured interval
5. Slack / Teams alerts fire when new findings exceed the severity threshold
