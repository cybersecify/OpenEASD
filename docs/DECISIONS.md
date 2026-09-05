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
**Status:** SUPERSEDED (2026-08-22) · **Decided:** 2026-05-22

> **Superseded.** Brand Protection has been retired — there is no separate paid
> product. The boundary this decision drew no longer applies. Capabilities it
> reserved for Brand Protection are now evaluated for OpenEASD on their own
> merits, with a simple filter: **is it free, does it fit OpenEASD's external
> attack-surface scope, and does it add real value?** Under that filter,
> **technology fingerprinting** is now in scope (httpx `-tech-detect`), and
> **infostealer/credential-leak** signal is under evaluation (free Hudson Rock
> endpoint, pending a ToS check). Typosquatting, brand impersonation, and A–F
> letter-grading remain out — not because of any product boundary, but because
> they are brand-monitoring, not external-attack-surface scanning. The original
> decision text is kept below for history.

**Original decision (2026-05-22).** OpenEASD and Brand Protection are intentionally distinct
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
- **No A–F letter grades, typosquatting, or brand impersonation.** These are
  brand-monitoring, not external-attack-surface scanning — out of scope by focus.
  (Technology fingerprinting and infostealer/credential-leak are no longer
  excluded — Brand Protection is retired; see the superseded
  [D-004](#d-004--product-boundary-openeasd-vs-brand-protection).)
- **No "AI-powered" features in copy.** Security community discounts that
  language. If we add real AI later (e.g. finding triage), describe what it
  actually does in plain terms.

---

## D-009 — v2.0 direction: Agentic AI / LLM-triage
**Status:** locked · **Decided:** 2026-05-31 · *Amended by [D-015](#d-015--v20-shipped-scope-triage--adaptive-orchestration--summaries) (2026-09-05)*

> **Amendment (D-015).** The direction stands; the scope widened. v2.0 ships
> triage plus two of the candidate scopes this entry set aside — adaptive
> orchestration (a bounded form of "multi-agent recon planning") and
> report/alert summaries — because they turned out to be thin consumers of
> triage's plumbing. See D-015 for the reasoning.

**What.** v2.0 will add an LLM-powered finding triage layer to OpenEASD — turning the scanner's raw output (76 findings, 3 critical, 21 high…) into a ranked, contextualised "fix this first" list with reasoning. Direction chosen over 4 other candidate scopes (chat-over-findings, auto-generated tool integrations, multi-agent recon planning, remediation playbooks) — see PRD.md v2.0 section.

**Why.** The OSS recon-tool wrapper space is saturated. Analyst-grade output is genuinely scarce. Backport-aware CVE matching (PR #56, [@turfin-logic](https://github.com/turfin-logic)) made the gap concrete: scanner output emits the same false-positive noise the underlying tools do, and the differentiation we can offer is *being smarter about the output than the tool we wrap*. LLM-triage extends that exact play from "filter out one class of false positive" to "rank everything by what actually matters."

**Hypothesis.** Triage is the highest-impact-per-token-spent scope of the 5 v2.0 candidates because (a) it's user-visible immediately on the existing scan-detail page (no new pages to build), (b) it has the lowest cost envelope per scan, (c) it directly answers the "scanner ≠ analyst" gap that backport-aware CVE matching exposed, (d) it demos well — a screenshot of "OpenEASD found 76 things; here are the 3 that actually matter and why" is a stronger marketing artifact than chat or planning sketches.

**Evidence.** Speculative on the demo-value claim (no v2.0 prototype exists yet). Data-oriented on the "saturated wrapper space" claim — `awesome-pentest`, `awesome-osint`, and `awesome-security` lists each contain dozens of recon-tool wrappers; few offer triage layered on top.

**Relationship to [D-008](#d-008--things-we-deliberately-dont-have-anti-features).** D-008 forbids *"AI-powered" in copy* — but explicitly allows real AI features described in plain terms. LLM-triage qualifies; marketing copy says what it does ("ranks findings by exploit-likelihood and explains why") not what it is ("AI-powered triage").

---

## D-010 — LLM-triage privacy stance: hybrid local + cloud opt-in
**Status:** SUPERSEDED (2026-09-05) · **Decided:** 2026-05-31

> **Superseded by [D-014](#d-014--v20-ai-backend-cloudflare-workers-ai-only-byok).**
> v2.0 ships with Cloudflare Workers AI as the only backend (BYOK); there is no
> local Ollama default and no separate cloud tier. The "results stay on your
> machine" claim survives as the *default* (AI is off until explicitly enabled
> with consent), which is the part of this decision D-014 keeps. The original
> text is kept below for history.

**What.** Local LLM (Ollama + Qwen 2.5 7B — see [D-011](#d-011--llm-triage-local-runtime--default-model)) is the default for everyone. Cloud API (Claude — see [D-012](#d-012--llm-triage-cloud-api-choice-claude-only-for-v20)) is a per-user opt-in with explicit consent (see [D-013](#d-013--llm-triage-consent-ux-shape)). Three other options were considered: local-only, cloud-only, and pluggable-from-day-one.

**Why.** OpenEASD's README hero explicitly claims "results stay on your machine" — load-bearing language for the security ICP (in-house security, bug bounty hunters, isolated/air-gapped scanning use cases). Cloud-only would silently break that claim and erode trust with exactly the audience we're trying to reach. Local-only would cap the v2.0 quality ceiling unnecessarily for users who explicitly want cloud-tier quality and consent to send their data. Hybrid keeps the default brand-safe and adds quality-on-consent.

**Hypothesis.** Brand-safe-by-default + explicit opt-in for cloud will (a) protect the "results stay on your machine" claim for the majority of users who never opt in, (b) allow a measurable upper bound on triage quality for the minority who do opt in, (c) provide a forcing function for a real consent UX that other "cloud AI inside an OSS tool" projects often skip.

**Evidence.** Data-oriented on the brand-claim risk — the README hero rewrite (commit `2c9caeb`) prominently features "Results stay on your machine" as a tagline; breaking it via undisclosed cloud calls would be a documented brand-incident class. Speculative on the consent-UX-as-differentiator claim — we don't have comparable OSS-with-cloud-LLM products to evaluate against.

---

## D-011 — LLM-triage local runtime + default model
**Status:** SUPERSEDED (2026-09-05) · **Decided:** 2026-05-31

> **Superseded by [D-014](#d-014--v20-ai-backend-cloudflare-workers-ai-only-byok).**
> There is no local runtime in v2.0 — no Ollama, no Qwen, no 8 GB hardware
> floor. Analysis quality no longer depends on host RAM. Original text kept
> below for history.

**What.** Local LLM backend = **Ollama** as the runtime, **Qwen 2.5 7B-Instruct** as the default model. User can override via config (`OPENEASD_LOCAL_LLM_MODEL` env var). Hardware floor: 8 GB RAM (the model needs ~5 GB; the rest is OpenEASD's existing footprint).

**Why.** Three alternatives considered: Llama 3.1 8B-Instruct (most popular community baseline; reasoning slightly weaker on long-context tasks), Phi-4 14B (stronger but 16 GB RAM hardware floor excludes some users), and pluggable-no-default (forces a first-run model picker, more UX complexity for marginal gain).

**Hypothesis.** Qwen 2.5 7B benchmarks well specifically on instruction-following and structured-output tasks — which is exactly what triage needs (output schema: ranked list with structured reasoning per item). Ollama is the canonical easy-install LLM runtime; most Docker hosts already have it or can install it cleanly. 8 GB RAM matches the realistic OpenEASD minimum.

**Evidence.** Speculative on the in-context Qwen-vs-Llama comparison — no eval suite has been run against actual OpenEASD finding outputs yet (prototype phase decision). Data-oriented on Ollama as runtime — popularity / install rate measurable via Ollama's GitHub star history and package-download numbers; significantly higher than llama.cpp direct, vLLM, or Hugging Face Transformers for "self-hosted LLM on a single box" use case.

---

## D-012 — LLM-triage cloud API choice: Claude only for v2.0
**Status:** SUPERSEDED (2026-09-05) · **Decided:** 2026-05-31

> **Superseded by [D-014](#d-014--v20-ai-backend-cloudflare-workers-ai-only-byok).**
> The single-provider reasoning here survives — v2.0 still integrates exactly
> one backend — but the provider is Cloudflare Workers AI (BYOK on the user's
> own account), not Anthropic's Claude API. Original text kept below for history.

**What.** Cloud-opt-in path uses **Anthropic's Claude API** as the only supported cloud backend in v2.0. Single integration. User configures via `ANTHROPIC_API_KEY` env var. Three alternatives were considered: OpenAI only, both Claude + OpenAI, and a multi-provider proxy framework (LiteLLM-style).

**Why.** v2.0 is a prototype. The design phase already has 6 more sub-decisions to make; adding a second SDK now compounds the surface area without proportional benefit. Claude's JSON-mode + tool-use is more predictable for structured triage output. Anthropic's no-training-on-API-data stance is the cleanest privacy story to tell security-paranoid users who consent to cloud.

**Hypothesis.** Shipping single-provider cleanly will (a) reduce time-to-prototype meaningfully vs. two-provider, (b) provide a single canonical consent-UX string to write ("your scan output is sent to Anthropic's Claude API") rather than per-provider variations, (c) let us learn whether the cloud path gets meaningful adoption before investing in second-provider support.

**Evidence.** Speculative on the adoption-driven-second-provider claim. Data-oriented on the single-provider time-savings — second SDK integration realistically adds 1-2 weeks of work to prototype timeline (separate auth, separate error handling, separate streaming model, separate prompt format).

**Follow-up trigger.** Add OpenAI as v2.1 if there's measurable user demand (3+ explicit requests, or visible cloud-opt-in adoption rate >25% after v2.0 ships and OpenAI-key users self-identify in Discussions).

---

## D-013 — LLM-triage consent UX shape
**Status:** locked · **Decided:** 2026-05-31 · *Amended by [D-014](#d-014--v20-ai-backend-cloudflare-workers-ai-only-byok) (2026-09-05)*

> **Amendment (D-014).** The 4-axis shape stays locked; wording and one axis
> adapt to the Cloudflare-only backend: consent names "Cloudflare Workers AI on
> your own account" instead of "Anthropic's Claude API"; because every AI call
> is a cloud call, consent gates *enabling AI at all* rather than choosing a
> cloud tier (4a's local/cloud toggle collapses into a single enable switch, and
> the per-scan override is replaced by a per-scan manual re-run); 4b–4d survive
> unchanged, with the 4c audit log now also recording purpose
> (triage / orchestration / summary) per call.

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

## D-014 — v2.0 AI backend: Cloudflare Workers AI only (BYOK)
**Status:** locked · **Decided:** 2026-09-05 · *Amended 2026-09-05*

> **Amendment (same day).** Credentials are no longer env-only: the operator
> can save the account ID + API token on the /ai page (stored in `AISettings`,
> write-only through the API — never serialized back out), with the
> `CLOUDFLARE_*` env vars as fallback (DB wins — the NotificationConfig
> webhook precedent). Trade-off accepted knowingly: the token now lives in
> the SQLite file, in exchange for a working setup path that doesn't require
> container restarts. Everything else in this decision stands.

**What.** The v2.0 AI layer uses **Cloudflare Workers AI** as its only backend, called directly from Django over Cloudflare's REST API. Credentials are strictly bring-your-own-key via environment variables (`CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`) — never stored in the database, never returned by the API. With either variable unset, or the feature disabled, or consent not recorded, the subsystem is invisible: every scan runs exactly as if the AI code did not exist. Default model `@cf/meta/llama-3.3-70b-instruct-fp8-fast`, overridable (`CLOUDFLARE_AI_MODEL`). The agent loop runs inside Django as Django-Q tasks — no Workers deployment, no AI Gateway. Supersedes [D-010](#d-010--llm-triage-privacy-stance-hybrid-local--cloud-opt-in), [D-011](#d-011--llm-triage-local-runtime--default-model), [D-012](#d-012--llm-triage-cloud-api-choice-claude-only-for-v20); amends [D-013](#d-013--llm-triage-consent-ux-shape) (wording + single enable switch).

**Why.** One integration instead of two (Ollama runtime + Claude SDK) for what is still a prototype — D-012 itself estimated 1–2 weeks per additional backend. Dropping the local runtime removes D-011's 8 GB RAM hardware floor entirely: a 1 GB `low`-profile host gets the same analysis quality as a 32 GB one, instead of being excluded or OOM-killing nuclei to fit a 5 GB model alongside it. BYOK keeps cost, rate limits, and the data-processing agreement on the user's own Cloudflare account (serverless per-call pricing, no resident model weights). The cost is real and stated honestly: enabling AI sends finding data off-box, so the README's "results stay on your machine" hero claim gets an explicit qualifier — it remains true for the default (off) state, which D-010 identified as the load-bearing part.

**Hypothesis.** BYOK-cloud-only with honest consent loses fewer users than it appears to: the privacy-sensitive majority keep the feature off and lose nothing, while users who enable it get hardware-independent quality and a per-call audit trail. Uniform quality also makes triage output testable against one model instead of a local-model matrix.

**Evidence.** Data-oriented on integration cost (D-012's own estimate) and on the hardware floor (D-011 set 8 GB; the `low` profile targets ~1 GB hosts — the conflict was documented, not hypothetical). Speculative on adoption and on Workers AI open-weight models being good enough for structured triage — no eval against real OpenEASD scan output exists yet; the JSON-schema-constrained output design is the mitigation.

**Follow-up trigger.** If schema-mismatch rates or triage quality complaints show the default model is not good enough, revisit model choice (config-only change) before revisiting backend choice.

---

## D-015 — v2.0 shipped scope: triage + adaptive orchestration + summaries
**Status:** locked · **Decided:** 2026-09-05

**What.** v2.0 ships three AI capabilities together on one framework: (1) **findings triage** — a ranked "fix these first" list with per-item rationale on the scan detail page; (2) **adaptive scan orchestration** — a bounded agent that may launch follow-up subscans based on results (hard caps on iterations and subscans; active tools still require `DomainAuthorization`, enforced again at the agent's own dispatch boundary); (3) **report and alert summaries** — a plain-language analyst paragraph in the PDF report and Slack/Teams alerts. Amends [D-009](#d-009--v20-direction-agentic-ai--llm-triage), which had narrowed v2.0 to triage only.

**Why.** The three scopes share one client, one consent gate, one audit trail, and one prompt-context builder — triage alone builds ~80% of the plumbing, and the other two are thin consumers of it. Shipping them together turns the demo from "a sorting hat for findings" into "an analyst that prioritises, digs deeper, and writes the summary," which is the v2.0 differentiation D-009 was after. D-008 still applies: copy describes what each capability does, never "AI-powered."

**Hypothesis.** The marginal cost of orchestration + summaries on top of triage is small enough (shared plumbing) that shipping all three beats sequencing them, and the combined demo is the stronger marketing artifact.

**Evidence.** Speculative — prototype-phase decision, same epistemic status as D-009's original single-scope bet. The bounded-loop safety design (iteration/subscan caps, authorization re-check, fail-graceful hooks) is the hedge against orchestration being the risky third of the scope.

---

## Index

| ID | Decision | Status | Decided |
|---|---|---|---|
| D-001 | Audience: security-literate users | locked | 2026-05-21 |
| D-002 | License: MIT | locked | 2026-04-24 |
| D-003 | Distribution: Docker-only | locked | 2026-04-24 |
| D-004 | Product boundary: OpenEASD vs Brand Protection | superseded | 2026-05-22 |
| D-005 | Verification discipline (claims-trace) | locked | 2026-05-20 |
| D-006 | Wording conventions per surface | locked | 2026-05-22 |
| D-007 | Canonical 11 attack vectors | locked | 2026-05-20 |
| D-008 | Anti-features (deliberate omissions) | locked | 2026-05-21 |
| D-009 | v2.0 direction: Agentic AI / LLM-triage | locked (amended by D-015) | 2026-05-31 |
| D-010 | LLM-triage privacy stance: hybrid local + cloud opt-in | superseded | 2026-05-31 |
| D-011 | LLM-triage local runtime + default model | superseded | 2026-05-31 |
| D-012 | LLM-triage cloud API choice: Claude only for v2.0 | superseded | 2026-05-31 |
| D-013 | LLM-triage consent UX shape | locked (amended by D-014) | 2026-05-31 |
| D-014 | v2.0 AI backend: Cloudflare Workers AI only (BYOK) | locked | 2026-09-05 |
| D-015 | v2.0 shipped scope: triage + orchestration + summaries | locked | 2026-09-05 |

---

*Add new decisions as `D-NNN`. Don't edit a locked decision in place — add
a follow-up entry that supersedes it, keep the old one for context. The
goal is a record you can read top-to-bottom and understand why the product
is shaped this way.*
