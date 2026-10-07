# tldsquatting — Email-Capable Severity + Fetch Prioritization

**Status:** accepted · **Date:** 2026-10-07 · **Type:** FP/FN-model refinement
**Supersedes nothing** — extends [tldsquatting FP Reduction](2026-09-30-tldsquatting-fp-reduction.md).

## Problem

A Passive Scan Deep review of several brand-heavy domains (stripe.com,
gitlab.com, hashicorp.com) showed ~70–90% of tldsquatting findings sitting at
`low` severity as individual `lookalike_domain` rows. Sampling their signals
revealed the LOW bucket is **not** inert noise — it hides deliberately-staged
impersonation infrastructure:

- stripe.com LOW (115): **40 have MX**, 30 have SPF/DMARC, `content_checked`=0 for all.
- gitlab.com LOW (86): 21 have MX, 22 have SPF/DMARC, `content_checked`=0 for all.
- Smoking gun: `gitlab.xyz` has **A + MX + SPF + DMARC** (threat_score 7.5, a
  MEDIUM band) yet is graded **LOW**.

Two compounding mechanisms cause this:

1. **The no-weaponization severity cap** (`analyzer.py`). It demotes any
   lookalike to `low` when there's no observed `login_form`/`brand_mentioned`
   **and** it has a live website (`has_a`/`has_aaaa`). Its one exemption is
   *email-only* lookalikes (mail records but **no** website) — guarded by
   `has_live_website`. A lookalike that has a website **and** a configured
   mail-auth stack therefore falls into the capped bucket: the model scored its
   mail infrastructure, and the cap threw that away.

2. **The content-fetch cap** (`collector.py`). Only the first
   `CONTENT_MAX_FETCHES` (25) A-bearing candidates get a homepage fetch, selected
   by **candidate-generation order** (TLD-swaps, then char mutations) — not by
   suspicion. On a large candidate set the mail-configured staging domains are
   usually never fetched, so `content_checked=False`, which *guarantees* the
   no-weaponization cap fires.

Net: minimum-cost attacker staging (register + nameserver + mail-auth stack,
no live phishing page yet) is exactly the shape that slips to LOW. This is a
false negative, and in a security scanner a false negative is worse than a
false positive.

## Fix 1 — email-capable lookalikes escape the no-weaponization cap

A lookalike carrying a **configured sender identity** — a mail server **and** an
SPF or DMARC policy (`has_mx AND (has_spf OR has_dmarc)`) — is impersonation
infrastructure in its own right (staged to send/receive authenticated mail as
the brand). It keeps its full mapped severity even with a website and no
inspected `login_form`/`brand_mentioned`.

Add an `email_capable` predicate to the cap condition in
`analyzer.analyze()`:

```python
email_capable = bool(record.get("has_mx")) and (
    bool(record.get("has_spf")) or bool(record.get("has_dmarc"))
)
capped = (
    no_weaponization_signal
    and has_live_website
    and not email_capable          # NEW — staged mail identity keeps its band
    and threat_level != "PRE-EXISTING"
    and severity in ("medium", "high", "critical")
)
```

**Deliberate threshold:** MX **plus** an auth record, not MX alone. A bare MX is
common on parked/default registrar setups (FP risk); MX + SPF/DMARC is a
deliberate, send-capable mail identity (the staging signal). MX-alone websites
stay capped as a monitoring signal — and Fix 2 prioritizes them for the content
inspection that can confirm or clear them. Email-*only* lookalikes (no website)
are unchanged: they already escape via `has_live_website=False`.

**Scope:** severity only. Classification is unchanged (these are already the
`threat` class → individual findings). Raw `risk_score`/`threat_score`/levels in
`extra` were already left uncapped and stay so.

## Fix 2 — spend the content-fetch budget on the most suspicious candidates

Replace the order-based slice with a suspicion-ranked one, and move the RDAP
registration-age enrichment **before** the fetch so recency is available to the
ranking:

```python
# (reordered) _enrich_registration_age(session, apex, results)  -- now BEFORE fetch
to_fetch = sorted(
    (r for r in results if r.get("has_a")),
    key=_fetch_priority, reverse=True,
)[:CONTENT_MAX_FETCHES]
```

`_fetch_priority` (pure, in `collector.py`) ranks by, in order: configured
mail-auth stack, recent registration (≤ 365 days), MX present, SPF/DMARC
present. A lookalike that **predates** the target is benign (`pre_existing`) and
sorts last so it never consumes the budget:

```python
def _fetch_priority(record) -> tuple:
    if record.get("predates_target"):
        return (-1, 0, 0, 0)
    has_mx = bool(record.get("has_mx"))
    has_auth = bool(record.get("has_spf") or record.get("has_dmarc"))
    email_capable = has_mx and has_auth
    age = _age_days(record.get("created"))
    recent = age is not None and age <= 365
    return (
        1 if email_capable else 0,
        1 if recent else 0,
        1 if has_mx else 0,
        1 if has_auth else 0,
    )
```

`sorted(..., reverse=True)` is stable, so equal-priority candidates keep their
original generation order (TLD-swaps still ahead of char mutations). `_age_days`
is reused from `scoring.py` (no new network, no circular import — `scoring`
imports nothing internal).

Reordering `_enrich_registration_age` ahead of the fetch is safe: it depends
only on the registered results + RDAP, never on content signals, and the fetch
depends only on candidate + brand + apex, never on RDAP.

## Expected impact (on the reviewed data)

- stripe.com: ~40 mail-configured lookalikes rise from LOW to their real band.
- gitlab.com: `gitlab.xyz` returns to MEDIUM.
- Genuinely inert bare registrations (A record, no mail, no brand, no login)
  stay LOW — the FP protection from the FP-reduction spec is preserved.
- The 25 content fetches land on recent + mail-configured candidates first, so
  staged domains get the homepage inspection that can escalate (login form /
  brand mention) or clear them, instead of the budget being spent on
  alphabetically-first TLD swaps.

## Tests

- `test_email_capable_lookalike_not_capped` — A + MX + SPF + DMARC, no
  login/brand → severity stays MEDIUM (replaces the old
  `test_no_weaponization_signal_caps_severity_to_low`, which asserted the
  now-fixed behavior).
- `test_plain_website_no_mail_still_capped_to_low` — A + unknown-tier NS, no
  mail, no login/brand, MEDIUM band → still capped to LOW.
- Email-only (`test_weighted_email_infra_combo_is_critical`,
  `test_email_only_phishing_prep_not_capped`) unchanged — still exempt.
- `test_fetch_priority_ranks_email_capable_first` /
  `_recent_before_old` / `_pre_existing_last` — pure `_fetch_priority` ordering.
- `test_collect_fetches_suspicious_candidates_within_cap` — with a cap of 1 and
  an email-capable candidate behind an inert one in generation order, the
  email-capable one is the one fetched.
