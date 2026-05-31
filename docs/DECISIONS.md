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

## D-009 — v2.0 direction: Agentic AI / LLM-triage
**Status:** locked · **Decided:** 2026-05-31

**What.** v2.0 will add an LLM-powered finding triage layer to OpenEASD — turning the scanner's raw output (76 findings, 3 critical, 21 high…) into a ranked, contextualised "fix this first" list with reasoning. Direction chosen over 4 other candidate scopes (chat-over-findings, auto-generated tool integrations, multi-agent recon planning, remediation playbooks) — see PRD.md v2.0 section.

**Why.** The OSS recon-tool wrapper space is saturated. Analyst-grade output is genuinely scarce. Backport-aware CVE matching (PR #56, [@turfin-logic](https://github.com/turfin-logic)) made the gap concrete: scanner output emits the same false-positive noise the underlying tools do, and the differentiation we can offer is *being smarter about the output than the tool we wrap*. LLM-triage extends that exact play from "filter out one class of false positive" to "rank everything by what actually matters."

**Hypothesis.** Triage is the highest-impact-per-token-spent scope of the 5 v2.0 candidates because (a) it's user-visible immediately on the existing scan-detail page (no new pages to build), (b) it has the lowest cost envelope per scan, (c) it directly answers the "scanner ≠ analyst" gap that backport-aware CVE matching exposed, (d) it demos well — a screenshot of "OpenEASD found 76 things; here are the 3 that actually matter and why" is a stronger marketing artifact than chat or planning sketches.

**Evidence.** Speculative on the demo-value claim (no v2.0 prototype exists yet). Data-oriented on the "saturated wrapper space" claim — `awesome-pentest`, `awesome-osint`, and `awesome-security` lists each contain dozens of recon-tool wrappers; few offer triage layered on top.

**Relationship to [D-008](#d-008--things-we-deliberately-dont-have-anti-features).** D-008 forbids *"AI-powered" in copy* — but explicitly allows real AI features described in plain terms. LLM-triage qualifies; marketing copy says what it does ("ranks findings by exploit-likelihood and explains why") not what it is ("AI-powered triage").

---

## D-010 — LLM-triage privacy stance: hybrid local + cloud opt-in
**Status:** locked · **Decided:** 2026-05-31

**What.** Local LLM (Ollama + Qwen 2.5 7B — see [D-011](#d-011--llm-triage-local-runtime--default-model)) is the default for everyone. Cloud API (Claude — see [D-012](#d-012--llm-triage-cloud-api-choice-claude-only-for-v20)) is a per-user opt-in with explicit consent (see [D-013](#d-013--llm-triage-consent-ux-shape)). Three other options were considered: local-only, cloud-only, and pluggable-from-day-one.

**Why.** OpenEASD's README hero explicitly claims "results stay on your machine" — load-bearing language for the security ICP (in-house security, bug bounty hunters, isolated/air-gapped scanning use cases). Cloud-only would silently break that claim and erode trust with exactly the audience we're trying to reach. Local-only would cap the v2.0 quality ceiling unnecessarily for users who explicitly want cloud-tier quality and consent to send their data. Hybrid keeps the default brand-safe and adds quality-on-consent.

**Hypothesis.** Brand-safe-by-default + explicit opt-in for cloud will (a) protect the "results stay on your machine" claim for the majority of users who never opt in, (b) allow a measurable upper bound on triage quality for the minority who do opt in, (c) provide a forcing function for a real consent UX that other "cloud AI inside an OSS tool" projects often skip.

**Evidence.** Data-oriented on the brand-claim risk — the README hero rewrite (commit `2c9caeb`) prominently features "Results stay on your machine" as a tagline; breaking it via undisclosed cloud calls would be a documented brand-incident class. Speculative on the consent-UX-as-differentiator claim — we don't have comparable OSS-with-cloud-LLM products to evaluate against.

---

## D-011 — LLM-triage local runtime + default model
**Status:** locked · **Decided:** 2026-05-31

**What.** Local LLM backend = **Ollama** as the runtime, **Qwen 2.5 7B-Instruct** as the default model. User can override via config (`OPENEASD_LOCAL_LLM_MODEL` env var). Hardware floor: 8 GB RAM (the model needs ~5 GB; the rest is OpenEASD's existing footprint).

**Why.** Three alternatives considered: Llama 3.1 8B-Instruct (most popular community baseline; reasoning slightly weaker on long-context tasks), Phi-4 14B (stronger but 16 GB RAM hardware floor excludes some users), and pluggable-no-default (forces a first-run model picker, more UX complexity for marginal gain).

**Hypothesis.** Qwen 2.5 7B benchmarks well specifically on instruction-following and structured-output tasks — which is exactly what triage needs (output schema: ranked list with structured reasoning per item). Ollama is the canonical easy-install LLM runtime; most Docker hosts already have it or can install it cleanly. 8 GB RAM matches the realistic OpenEASD minimum.

**Evidence.** Speculative on the in-context Qwen-vs-Llama comparison — no eval suite has been run against actual OpenEASD finding outputs yet (prototype phase decision). Data-oriented on Ollama as runtime — popularity / install rate measurable via Ollama's GitHub star history and package-download numbers; significantly higher than llama.cpp direct, vLLM, or Hugging Face Transformers for "self-hosted LLM on a single box" use case.

---

## D-012 — LLM-triage cloud API choice: Claude only for v2.0
**Status:** locked · **Decided:** 2026-05-31

**What.** Cloud-opt-in path uses **Anthropic's Claude API** as the only supported cloud backend in v2.0. Single integration. User configures via `ANTHROPIC_API_KEY` env var. Three alternatives were considered: OpenAI only, both Claude + OpenAI, and a multi-provider proxy framework (LiteLLM-style).

**Why.** v2.0 is a prototype. The design phase already has 6 more sub-decisions to make; adding a second SDK now compounds the surface area without proportional benefit. Claude's JSON-mode + tool-use is more predictable for structured triage output. Anthropic's no-training-on-API-data stance is the cleanest privacy story to tell security-paranoid users who consent to cloud.

**Hypothesis.** Shipping single-provider cleanly will (a) reduce time-to-prototype meaningfully vs. two-provider, (b) provide a single canonical consent-UX string to write ("your scan output is sent to Anthropic's Claude API") rather than per-provider variations, (c) let us learn whether the cloud path gets meaningful adoption before investing in second-provider support.

**Evidence.** Speculative on the adoption-driven-second-provider claim. Data-oriented on the single-provider time-savings — second SDK integration realistically adds 1-2 weeks of work to prototype timeline (separate auth, separate error handling, separate streaming model, separate prompt format).

**Follow-up trigger.** Add OpenAI as v2.1 if there's measurable user demand (3+ explicit requests, or visible cloud-opt-in adoption rate >25% after v2.0 ships and OpenAI-key users self-identify in Discussions).

---

## D-013 — LLM-triage consent UX shape
**Status:** locked · **Decided:** 2026-05-31

**What.** Four sub-axes of the consent UX for cloud-backed LLM triage:

| Axis | Decision |
|---|---|
| **4a — *Where* the toggle lives** | Account-level default ("local" by default) + per-scan override on the scan-detail triage view |
| **4b — *When* consent is captured** | First-use modal — one-time, "your scan output will be sent to Anthropic's Claude API; continue?" with a "don't show again" checkbox |
| **4c — Audit log granularity** | Medium — per cloud call, log: timestamp + scan UUID + backend (claude/local) + token count + finding IDs included in the prompt. Don't store the prompt or response content (sensitive) |
| **4d — Revocability** | Future-only — toggle off → no new cloud calls. v2.1 can add audit-purge if user demand surfaces. Anthropic API deletion DSR is manual via support; not automating in v2.0 |

**Why.** Default-local + first-use modal + audit log + future-only-revoke is the smallest consent UX that's still honest. Each smaller variant (no modal, no audit) leaks trust; each larger variant (per-action confirmation, full prompt logging, automated DSR) adds friction or surface area without commensurate value for v2.0.

**Hypothesis.** Minimal-honest consent UX will (a) cause near-zero friction for the local-default majority who never opt in to cloud (they never see the modal), (b) cause meaningful-but-not-prohibitive friction for users who consent (one modal, then frictionless until they explicitly revoke), (c) produce a defensible audit trail that's useful for the "what got sent where" question without storing the actually-sensitive prompt content.

**Evidence.** Speculative on the friction-vs-trust trade-off curve — no A/B test data exists for this product. Pattern is similar to how Sentry handles "send error events to our cloud" (account-level default + per-scope override + audit log without full event bodies) and to how some EDR products handle their cloud-eval consent (first-use modal). Data-oriented on the modal-burden claim — UX research literature (e.g. NN/g) generally agrees one-time consent + "don't show again" is the lowest-friction informed-consent pattern.

**Follow-up trigger.** v2.1 should add audit-log-purge if ≥3 users in Discussions ask for "I want to delete my own audit log entries." Don't pre-build it.

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
| D-009 | v2.0 direction: Agentic AI / LLM-triage | locked | 2026-05-31 |
| D-010 | LLM-triage privacy stance: hybrid local + cloud opt-in | locked | 2026-05-31 |
| D-011 | LLM-triage local runtime + default model | locked | 2026-05-31 |
| D-012 | LLM-triage cloud API choice: Claude only for v2.0 | locked | 2026-05-31 |
| D-013 | LLM-triage consent UX shape | locked | 2026-05-31 |

---

*Add new decisions as `D-NNN`. Don't edit a locked decision in place — add
a follow-up entry that supersedes it, keep the old one for context. The
goal is a record you can read top-to-bottom and understand why the product
is shaped this way.*
