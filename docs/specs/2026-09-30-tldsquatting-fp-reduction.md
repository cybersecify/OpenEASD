# tldsquatting False-Positive Reduction — Design Spec

> **Status:** ✅ Implemented — shipped on `feat/tldsquatting-fp-reduction`
> (`apps/tldsquatting/classify.py` + the analyzer collapse/rollup path +
> `TLDSQUATTING_COLLAPSE_BENIGN`). Design agreed via brainstorming (output
> behavior = collapse benign into rollups; unrelated handling = conservative
> override — see §3/§4); built to this contract.

**Goal:** Shrink tldsquatting output on large brands from *hundreds* of individual
lookalike findings to a **readable handful of real threats plus a few info
rollups**, without dropping anything or hiding a real impersonation. Triaging live
scans of freshworks.com / postman.com / zoho.com surfaced 49 / 101 / 167 **MEDIUM
lookalike** findings each — overwhelmingly the company's **own** domains, **parked/
for-sale** domains, or **unrelated** businesses with a similar name.

**Owner:** OpenEASD core (`apps/tldsquatting`). **Depends on:** the ported scoring
model (`scoring.py`, unchanged) and the v2.23.0 no-weaponization severity cap (kept).
**Scope:** one tool, self-contained; the **passive contract is preserved** (the
target's own systems are never contacted — target baseline is gathered via public
DNS/RDAP only).

---

## 1. Motivation

For a small brand the lookalike list is short and mostly signal. For a large SaaS
brand it explodes: Zoho alone produced ~167 MEDIUM lookalikes, the vast majority of
which are **not threats** — Zoho's own ccTLD/defensive registrations, parked domains
on a parking service, or genuinely unrelated companies. The v2.23.0 cap already
downgrades no-weaponization lookalikes to LOW (severity), but it does **not reduce
the count** — a defender still scrolls past 167 rows. This spec adds a
**classification + collapse** layer so the benign majority becomes a few auditable
summary findings and only real threats stay individual.

---

## 2. New passive signals (collector)

Classifying *owned* / *unrelated* needs the **target's own baseline**. All of it is
passive (public resolvers / RDAP — the org's systems are never contacted, preserving
the tool's contract):

- **`target_ns`** — the apex's authoritative NS host set, resolved once per scan via
  a public resolver. Normalized lowercase, registrable-domain compared (so
  `ns1.zoho.com` and `ns2.zoho.com` both reduce to the `zoho.com` NS operator).
- **`target_registrant` / `target_registrar`** — from the target's RDAP response
  (the collector already performs target RDAP for `created`; extend it to capture the
  registrant org/handle and registrar string when present and not redacted).

Per-candidate signals already gathered and reused as-is: `ns_targets`,
`resolved_ips`, `parked`, `brand_mentioned`, `brand_mention_count`, `login_form`,
`has_a`/`has_mx`/…, `created` / `predates_target`, `technique`, `content_checked`.

---

## 3. Classification

A new **pure** function `classify_lookalike(record, target_ns, target_registrant,
target_registrar) -> str` returns exactly one class. Precedence is top-down (first
match wins):

| # | Class | Rule |
|---|---|---|
| 1 | `pre_existing` | `record["predates_target"]` is true (a domain older than the target can't be squatting it — the existing PRE-EXISTING rule). |
| 2 | `owned` | candidate `ns_targets` share a registrable NS operator with `target_ns` **OR** candidate registrant (RDAP) equals `target_registrant` (both present, non-redacted). Positive-match only. |
| 3 | `parked` | `record["parked"]` (parking NS tier, parking IP, or for-sale/parked content). |
| 4 | `unrelated` | different NS operator from the target **AND** `not brand_mentioned` **AND** serves its own content (`has_a` and `content_checked` and not parked). |
| 5 | `threat` | everything else. |

**Forcing rules (false-negative safety — override the table above):** a candidate is
**always `threat`** (never 1–4 except `pre_existing`) when **any** of:
- `brand_mentioned` is true (a real impersonator represents your brand), **or**
- the email-only phishing-prep fingerprint holds (`has_mx and not has_a`, or
  `has_spf`/`has_dmarc` without a website).

`owned` still wins over these forcing rules only via the NS/registrant *positive
match* — i.e. a domain on **your** nameservers that mentions your brand is *yours*
(brand mention on your own domain is expected), which is safe because an attacker
cannot publish on your authoritative NS.

---

## 4. Output — collapse benign, keep threats individual (analyzer)

Group this scan's candidates by class, then:

- **`owned` / `parked` / `unrelated` / `pre_existing`** → emit **one `info` rollup
  Finding per non-empty class**:
  - `check_type`: `lookalike_owned` / `lookalike_parked` / `lookalike_unrelated` /
    `lookalike_pre_existing`; `source="tldsquatting"`; `severity="info"`.
  - title e.g. *"12 owned lookalike domains (share nameservers/registrant with
    zoho.com)"*.
  - `extra["domains"]` = the full list, each `{domain, technique, reason,
    risk_score, threat_score, threat_level, created}` — **fully auditable, nothing
    dropped**.
- **`threat`** → **individual findings**, exactly as today: the ported
  `scoring.py` risk/threat scores map to severity, and the **v2.23.0
  no-weaponization cap still applies** within this class. `check_type` stays
  `lookalike_domain` so `asn_cluster` (which consumes `high`/`critical`
  `lookalike_domain` findings) is unaffected.

**Interaction with `asn_cluster`:** unchanged — it reads individual
`lookalike_domain` findings. Collapsed (benign) domains no longer emit individual
`lookalike_domain` findings, so `asn_cluster` naturally clusters only the `threat`
class, which is the desired behavior (benign owned/parked domains shouldn't drive
"lookalike cluster" campaign findings).

---

## 5. Settings

| Setting | Default | Effect |
|---|---|---|
| `TLDSQUATTING_COLLAPSE_BENIGN` | `True` | Master toggle. `False` reverts to per-domain findings for every class (current behavior) — a debug/safety escape hatch. |

---

## 6. Report

The PDF/report renderer shows each rollup as its title (with count) plus the
`extra["domains"]` list (domain + reason), so every collapsed domain remains visible
and auditable in the report body or an appendix. Absent the rollups (feature off, or
no benign lookalikes), the report is unchanged.

---

## 7. Files

- `apps/tldsquatting/collector.py` — gather `target_ns` + registrant/registrar
  (passive); attach to each record or pass alongside.
- `apps/tldsquatting/classify.py` *(new, pure)* — `classify_lookalike(...)`.
- `apps/tldsquatting/analyzer.py` — group by class; emit rollups for benign classes,
  individual findings for `threat` (existing scoring/cap path).
- `apps/tldsquatting/scoring.py` — **untouched.**
- `openeasd/settings/base.py` — `TLDSQUATTING_COLLAPSE_BENIGN`.
- report template — render rollup domain lists.
- `docs/03-system.md` / `CLAUDE.md` — document the classification + rollup behavior.

---

## 8. Design invariants (to be guarded by tests)

- A candidate with `brand_mentioned` is **never** classified `owned`/`parked`/
  `unrelated` (except `pre_existing`) — always `threat`.
- The email-only phishing-prep fingerprint is **never** collapsed — always `threat`.
- `owned` requires a **positive** NS/registrant match; an attacker-controlled domain
  (different NS, no shared registrant) can never be classified `owned`.
- `unrelated` requires **different NS AND no brand mention AND own content** — a
  login form alone does not keep a stranger's domain elevated, and a brand mention
  always pulls it back to `threat`.
- Benign classes collapse to `info` rollups whose `extra["domains"]` lists every
  member (auditable); the `threat` class emits individual `lookalike_domain`
  findings with unchanged scoring + the v2.23.0 cap.
- `TLDSQUATTING_COLLAPSE_BENIGN=False` ⇒ per-domain findings for all classes
  (pre-feature behavior).
- Fully passive: no new request ever targets the org's own systems (target baseline
  via public DNS/RDAP only).

---

## 9. Documented residual false-negative

A phishing site hosted on its **own** nameservers that shows the brand only as a
**logo image** (no brand *text*) with a login form and zero textual brand mention
would be classified `unrelated` and collapsed to the info rollup (text-based
`brand_mentioned` misses image-only branding). This is the mild, accepted trade-off
of the conservative-override decision; the `different-NS + no-text-brand` gate keeps
it narrow, the domain is still listed (auditable) in the rollup, and it re-classifies
to `threat` the moment any brand text appears. Image-based brand detection is out of
scope (a future enhancement).
