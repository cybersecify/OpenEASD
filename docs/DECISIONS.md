# OpenEASD — Decisions

This is the **why** alongside the code. Whenever someone (a contributor, a
future-us, an evaluator) asks "why MIT and not fair-code?" or "why no hosted
scan?", the answer should be here, not buried in commit history or memory.

Each entry has a **status** — `locked` means we've decided and aren't
re-litigating without a strong reason; `open` means we're still working it
out; `under-review` means there's a scheduled date to revisit.

> If you disagree with a locked decision, open an issue with the specific
> assumption you think is wrong, not a counter-proposal. The fastest way
> through is to invalidate the premise.

---

## D-001 — Audience: security-literate users, not non-technical end users
**Status:** locked · **Decided:** 2026-05-21

**Decision.** OpenEASD's primary audience is the security community — in-house
security engineers, IT engineers handed security responsibility, small
security consultancies, security learners. Users know what nuclei / subfinder /
nmap are; they just prefer a GUI over orchestrating CLIs by hand.

**Not targeting.** Bug bounty hunters / elite red-teamers (they prefer raw
CLI speed). Enterprise SOCs (no RBAC/SAML/HA/Postgres). Genuinely non-technical
users (the Workflows page and tool-name labels would confuse them).

**Why.** The codebase already maps to this audience: scheduled scans, alerts,
finding lifecycle, multi-domain support, JWT auth, PDF reports. Trying to
serve non-tech users would require a 2–4 week UX overhaul (workflow presets,
plain-language tool descriptions, "what does this mean" expansions on findings).
We chose to ship for the audience the code already serves well and be honest
about it.

---

## D-002 — License: MIT, not SUL or fair-code
**Status:** locked · **Decided:** 2026-04-24

**Decision.** OpenEASD is MIT-licensed and stays MIT. Not switching to
n8n-style Sustainable Use License or any other fair-code variant.

**Why.** *Open source is the structural differentiator.* The contribution we
want to give back to the security community is the freedom — fair-code adds
restrictions (no hosted-SaaS-on-top, etc.) that the community treats as
"open-ish, not open." A user evaluating us next to genuine OSS competitors
(reNgine, the ProjectDiscovery suite) would treat a fair-code OpenEASD as
strictly worse. MIT removes that friction.

**Revisit when.** Someone builds a commercial SaaS on top of OpenEASD that
materially harms us. Even then, switching is hard (relicensing requires
all-contributor consent for their commits) — better to plan for it
contractually than rely on a license change.

---

## D-003 — Distribution: Docker-only
**Status:** locked · **Decided:** 2026-04-24

**Decision.** OpenEASD ships as `ghcr.io/cybersecify/openeasd:latest` and
Kubernetes manifests in `k8s/`. We do **not** offer a hosted/SaaS scan,
even as a "try it before you self-host" funnel.

**Why.** A hosted "scan any domain" service needs a domain-ownership
verification path so we don't become recon-as-a-service for bad actors
(every public scanner in this space eventually gets abused this way). That
verification path is real engineering work, and bandwidth to operate it
isn't there. Until the math changes, Docker-only.

**Revisit when** *all three* of these are true:
- 100+ GitHub stars on the public repo
- A workable verification path designed (TXT record? DNS challenge? email-on-WHOIS?)
- Operational bandwidth to run the service (not just code it)

Scheduled review: 2026-05-25 (just a check-in date; the triggers gate the
real decision).

---

## D-004 — Product boundary: OpenEASD vs Brand Protection
**Status:** locked · **Decided:** 2026-05-22

**Decision.** OpenEASD and Brand Protection are intentionally distinct
products with intentionally distinct audiences and outputs.

| | OpenEASD | Brand Protection |
|---|---|---|
| Audience | Security community / self-hosters | Paying customers |
| Pricing | Free, open source | Paid SaaS (planned) |
| Scope | External attack surface — DNS, ports, TLS, CVEs, web vulns | Typosquatting, brand impersonation, leaked credentials, technology fingerprinting, A-F grade |
| License | MIT | Proprietary |

**Why.** This separation is the *basis of the business model* — OpenEASD
builds community trust and goodwill; Brand Protection is the revenue product.
Blurring the boundary (e.g. moving typosquatting detection into OpenEASD,
or trying to charge for OpenEASD features) collapses both stories at once.

**How to apply.** Brand-Protection-specific claims (typosquatting, brand
impersonation, leaked credentials, technology fingerprinting, A-F grade)
must not appear in OpenEASD's README, frontend copy, PDF report templates,
or `/api/docs`. The reverse is also true: OpenEASD's specific tool list
shouldn't be promised on the BP landing page.

---

## D-005 — Verification discipline: claims must trace to source code
**Status:** locked · **Decided:** 2026-05-20

**Decision.** Every claim in customer-facing copy must trace to a specific
line in source code (an analyzer, a scanner, a model field). README phrasing
**does not count as evidence** — README itself can drift from code.

**Why.** A real prior incident: the cybersecify.com page claimed an HSTS
check; `apps/web_checker/analyzer.py` had no Strict-Transport-Security
check. The drift was caught only on the second review. The lesson: README
is a copy of code, not the source-of-truth — only the code is the
source-of-truth.

**How to apply.** Before any customer-facing copy lands (page, README, blog),
grep `apps/*/analyzer.py` and `apps/*/scanner.py` for the claimed behavior.
If it's not in code, either remove the claim or build the check first.

---

## D-006 — Wording conventions per surface
**Status:** locked · **Decided:** 2026-05-22

**Decision.** "External, non-intrusive" is the customer-facing description;
"passive" is correct for technical documentation. These are different
surfaces with different rules:

| Surface | Use | Avoid |
|---|---|---|
| **cybersecify.com/openeasd** (customer-facing copy, landing pages, PDF report intro) | "external, non-intrusive" | "passive" / "passive scanning" — sounds dismissive to non-technical buyers |
| **OpenEASD README, /api/docs, dev docs** (technical) | "passive" (subfinder), "active" (amass), "non-intrusive" wherever accurate | Marketing words ("AI-powered", "enterprise-grade", "next-gen") — security community will roast them |

**Why.** Two audiences, two vocabularies. Technical readers expect the
passive/active distinction (it's how recon tools are categorized).
Customer-facing readers don't have that context and "passive" reads as
"weak." Trying to use one vocabulary on both surfaces ends up underselling
to one and patronizing the other.

---

## D-007 — Canonical 11 attack vectors (customer-facing)
**Status:** locked · **Decided:** 2026-05-20

**Decision.** When listing what OpenEASD does in customer copy, use these
11 vectors (in this order):

1. Subdomain Discovery
2. Open Ports
3. DNS Security (DNSSEC / CAA / AXFR / wildcard / lame-delegation)
4. Email Security (MTA-STS / TLS-RPT / BIMI)
5. TLS/SSL
6. SSH Configuration Audit
7. CVE Detection (Nmap NSE + 319 Nuclei templates)
8. Domain Registration Health (RDAP)
9. Web Probing & URL Discovery (httpx)
10. Web Vulnerability Scanning (Nuclei community)
11. HTTP Security Headers / Cookies / CORS (Web Checker)

**Note on 11 vs 13.** The internal pipeline has 13 phases. Internal phases
like `service_detection` aren't customer-facing vectors — they're
classification steps that feed other tools. Don't reconcile 11 and 13;
they're different abstractions.

---

## D-008 — Things we deliberately don't have (anti-features)
**Status:** locked · **Decided:** 2026-05-21

Calling these out so contributors don't add them back without a discussion:

- **No RBAC / SAML / multi-tenant.** Single admin user, JWT auth. Anyone needing
  multi-user belongs on a different tool.
- **No Postgres / horizontal scaling.** SQLite + `replicas: 1`. The constraint is
  intentional — keeps the install one `docker run`. Postgres support is fine
  to add later but not the priority.
- **No hosted scan UI.** See [D-003](#d-003--distribution-docker-only).
- **No A–F grades, leaked credentials, typosquatting, brand impersonation,
  technology fingerprinting.** Those belong to Brand Protection — see
  [D-004](#d-004--product-boundary-openeasd-vs-brand-protection).
- **No "AI-powered" features in copy.** Security community discounts that
  language. If we add real AI later (e.g. finding triage), describe what it
  actually does in plain terms.

---

## Index

| ID | Decision | Status | Decided |
|---|---|---|---|
| D-001 | Audience: security-literate users | locked | 2026-05-21 |
| D-002 | License: MIT | locked | 2026-04-24 |
| D-003 | Distribution: Docker-only | locked | 2026-04-24 |
| D-004 | Product boundary: OpenEASD vs Brand Protection | locked | 2026-05-22 |
| D-005 | Verification discipline (claims-trace) | locked | 2026-05-20 |
| D-006 | Wording conventions per surface | locked | 2026-05-22 |
| D-007 | Canonical 11 attack vectors | locked | 2026-05-20 |
| D-008 | Anti-features (deliberate omissions) | locked | 2026-05-21 |

---

*Add new decisions as `D-NNN`. Don't edit a locked decision in place — add
a follow-up entry that supersedes it, keep the old one for context. The
goal is a record you can read top-to-bottom and understand why the product
is shaped this way.*
