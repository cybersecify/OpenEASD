"""tldsquatting analyzer — turns registered-lookalike records into shared Findings.

Each registered lookalike domain is first classified (``classify.py``) into
``owned`` / ``parked`` / ``unrelated`` / ``pre_existing`` / ``threat`` from
signals the collector gathered plus the passive target baseline
(``target_ns`` / ``target_registrant`` / ``target_registrar``, stamped on
every record by the collector). ``threat``-classified lookalikes always get
their own Finding (``check_type="lookalike_domain"`` — the same check_type
the former typosquat tool used, so ``asn_cluster`` consumes these findings
unchanged). The benign classes are, by default (``TLDSQUATTING_COLLAPSE_BENIGN``),
collapsed into a single ``info`` rollup Finding per non-empty class
(``check_type="lookalike_<class>"``) so a domain that owns 40 defensive
TLD registrations doesn't flood the report with 40 near-identical findings.
Toggling the setting off restores one Finding per domain for every class
(pre-feature behavior).

Severity for an individual (``threat``) Finding is the band of a ported
two-stage score (``scoring.py``):

  * ``calculate_risk_score`` scores registration timing + DNS posture. Its
    dominant rule is **PRE-EXISTING** — a lookalike that IS the apex or was
    registered *before* the target (the ``amnic.net`` case) scores 0.0 and is
    reported as ``info`` (it cannot be impersonating a domain younger than it).
  * ``calculate_threat_score`` adds live weaponization signals (login form,
    brand mentions, parked) from the homepage probe.

The final **threat level** maps to Finding severity:
``PRE-EXISTING→info, LOW→low, MEDIUM→medium, HIGH→high, CRITICAL→critical``.
The numeric scores + levels + creation dates land in ``extra`` so a defender
(and the report / AI triage) can see exactly what drove the rating. Rollup
Findings carry the same per-domain scores in ``extra["domains"]``.
"""

import logging

from django.conf import settings

from apps.core.data.findings.models import Finding

from .classify import CLASSES, classify_lookalike, ns_operators
from .scoring import calculate_risk_score, calculate_threat_score

logger = logging.getLogger(__name__)

# Threat level → Finding severity.
_SEVERITY_BY_LEVEL = {
    "PRE-EXISTING": "info",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}

# Short human explanation of why a class was treated as benign, reused both in
# the rollup description and per-domain "reason" entries.
_REASON_BY_CLASS = {
    "owned": "same nameservers/registrant as the target — you (or an affiliate) "
             "own this lookalike",
    "parked": "parked / dormant domain, no live content observed",
    "unrelated": "resolves independently and serves its own, unrelated content",
    "pre_existing": "registered before the target domain; cannot be "
                     "impersonating it",
}

# Rollup title phrase per class (formatted with the apex domain).
_TITLE_BY_CLASS = {
    "owned": "owned lookalike domains (share nameservers/registrant with {apex})",
    "parked": "parked lookalike domains (dormant, no live content)",
    "unrelated": "unrelated lookalike domains (serve independent content, not "
                 "impersonating {apex})",
    "pre_existing": "pre-existing lookalike domains (registered before {apex}, "
                     "cannot be impersonating it)",
}


def _first(records, key):
    """First non-None value for ``key`` across ``records``, else ``None``."""
    for record in records or []:
        value = record.get(key)
        if value is not None:
            return value
    return None


def _record_summary(record: dict) -> str:
    parts = []
    if record.get("has_a"):
        ips = ", ".join(record.get("resolved_ips") or []) or "yes"
        parts.append(f"A ({ips})")
    if record.get("has_aaaa"):
        parts.append("AAAA")
    if record.get("has_mx"):
        parts.append("MX (can receive mail)")
    if record.get("has_spf"):
        parts.append("SPF")
    if record.get("has_dmarc"):
        parts.append("DMARC")
    if record.get("has_dnssec"):
        parts.append("DNSSEC")
    if record.get("has_ns") and not (record.get("has_a") or record.get("has_mx")):
        parts.append("NS only (registered / parked)")
    return ", ".join(parts) or "registered"


def _drivers(record: dict, apex: str, level: str) -> str:
    """One human sentence explaining what drove the rating."""
    created = record.get("created")
    target_created = record.get("target_created")

    if level == "PRE-EXISTING":
        return (
            f"It was registered {created or 'before your domain'}, which PREDATES "
            f"{apex} ({target_created or 'unknown'}) — a domain older than yours "
            "cannot be impersonating it. This is very likely a legitimate or "
            "unrelated registrant; confirm it isn't one you own, but deprioritise it."
        )

    signals: list[str] = []
    if record.get("login_form"):
        signals.append("its live homepage shows a login form (credential phishing)")
    if record.get("brand_mentioned"):
        signals.append("its homepage mentions your brand")
    if record.get("has_mx") and not record.get("has_a"):
        signals.append("it carries email infrastructure but no website (email-spoofing setup)")
    elif record.get("has_a"):
        signals.append("it resolves and can serve web content")
    if record.get("parked"):
        signals.append("it currently sits on a domain-parking / for-sale service")
    if created:
        signals.append(f"registered {created}")

    lead = {
        "CRITICAL": "This is an active, weaponized impersonation — prioritise a takedown.",
        "HIGH": "This is a weaponizable brand threat — investigate and monitor closely.",
        "MEDIUM": "This lookalike carries real infrastructure — worth monitoring.",
        "LOW": "This is a registered but largely dormant lookalike — monitor it.",
    }.get(level, "Registered lookalike.")

    detail = ("; ".join(signals) + ".") if signals else "It is registered."
    return f"{lead} Drivers: {detail}"


def _score_record(record: dict, apex: str) -> tuple[float, str, float, str, bool]:
    """Shared risk/threat scoring for one record. Pure — no side effects.

    Returns ``(risk_score, risk_level, threat_score, threat_level, is_apex)``.
    """
    candidate = record.get("candidate") or ""
    target_created = record.get("target_created")
    is_apex = candidate.strip().lower() == apex if apex else False

    risk_score, risk_level = calculate_risk_score(
        record, target_created=target_created, is_apex=is_apex,
    )
    if risk_level == "PRE-EXISTING":
        # A domain that predates the target cannot be squatting it — the live
        # weaponization signals don't apply, so it stays a non-threat.
        threat_score, threat_level = 0.0, "PRE-EXISTING"
    else:
        threat_score, threat_level = calculate_threat_score(record, risk_score)

    return risk_score, risk_level, threat_score, threat_level, is_apex


def _individual_finding(session, apex: str, record: dict) -> Finding:
    """Build one Finding for a single registered lookalike domain.

    Behavior is unchanged from the pre-classification analyzer: severity is
    the mapped threat band, capped to ``low`` when there's no live
    weaponization evidence on an otherwise-resolving lookalike.
    """
    candidate = record.get("candidate")
    target_created = record.get("target_created")

    risk_score, risk_level, threat_score, threat_level, _is_apex = _score_record(record, apex)

    severity = _SEVERITY_BY_LEVEL.get(threat_level, "low")

    # Cap severity when there's no LIVE weaponization signal on an
    # ordinary resolving website. Infra alone (A/MX/SPF/DMARC/etc.) can
    # push the raw threat band to medium/high/critical, but without an
    # observed login form or brand mention on the lookalike's homepage
    # there is zero evidence of active impersonation — that's a
    # monitoring signal, not an incident. This cap must NOT apply to an
    # email-only lookalike (MX/SPF/DMARC but no A/AAAA) — that's the
    # model's strongest phishing-prep fingerprint (spoofing setup with no
    # website to inspect for a login form in the first place), so it
    # keeps its full mapped severity. The raw risk_score/threat_score/
    # levels are left untouched in `extra` either way.
    no_weaponization_signal = not record.get("login_form") and not record.get("brand_mentioned")
    has_live_website = bool(record.get("has_a") or record.get("has_aaaa"))
    # A lookalike carrying a configured sender identity — a mail server AND an
    # SPF/DMARC policy — is staged to send/receive authenticated mail as the
    # brand: impersonation infrastructure in its own right, even with a website
    # and no inspected login form / brand mention. It keeps its full mapped
    # severity (the minimal-but-deliberate phishing-staging shape would otherwise
    # be buried at low). MX alone (common on parked/default setups) is NOT enough
    # — it stays capped as a monitoring signal; the fetch pass prioritises it for
    # the content inspection that can confirm or clear it. Email-ONLY lookalikes
    # (no website) already escape the cap via has_live_website=False.
    email_capable = bool(record.get("has_mx")) and (
        bool(record.get("has_spf")) or bool(record.get("has_dmarc"))
    )
    capped = (
        no_weaponization_signal
        and has_live_website
        and not email_capable
        and threat_level != "PRE-EXISTING"
        and severity in ("medium", "high", "critical")
    )
    if capped:
        severity = "low"

    summary = _record_summary(record)
    drivers = _drivers(record, apex, threat_level)
    if capped:
        drivers += (
            " (Severity capped to low: no active-impersonation evidence "
            "observed — treat as a monitoring signal.)"
        )

    return Finding(
        session=session,
        source="tldsquatting",
        check_type="lookalike_domain",
        severity=severity,
        target=candidate,
        title=f"Registered lookalike domain {candidate} (targets {apex})",
        description=(
            f"{candidate} is a registered lookalike of {apex}, generated by the "
            f"'{record.get('technique', 'typo')}' technique. DNS records seen: "
            f"{summary}. Threat level {threat_level} "
            f"(risk {risk_score}, threat {threat_score}). {drivers}"
        ),
        remediation=(
            "Confirm the domain is not one you own. Monitor it for changes "
            "(new A/MX/TLS records), consider defensively registering the most "
            "convincing lookalikes, and report clear phishing infrastructure to "
            "the registrar / hosting provider for takedown."
        ),
        extra={
            "candidate": candidate,
            "technique": record.get("technique"),
            "has_a": bool(record.get("has_a")),
            "has_aaaa": bool(record.get("has_aaaa")),
            "has_mx": bool(record.get("has_mx")),
            "has_ns": bool(record.get("has_ns")),
            "has_cname": bool(record.get("has_cname")),
            "has_txt": bool(record.get("has_txt")),
            "has_spf": bool(record.get("has_spf")),
            "has_dmarc": bool(record.get("has_dmarc")),
            "has_caa": bool(record.get("has_caa")),
            "has_dnssec": bool(record.get("has_dnssec")),
            "resolved_ips": record.get("resolved_ips") or [],
            "ns_targets": record.get("ns_targets") or [],
            "login_form": bool(record.get("login_form")),
            "parked": bool(record.get("parked")),
            "brand_mentioned": bool(record.get("brand_mentioned")),
            "brand_mention_count": record.get("brand_mention_count", 0),
            "content_checked": bool(record.get("content_checked")),
            "https_enabled": bool(record.get("https_enabled")),
            "ssl_valid": bool(record.get("ssl_valid")),
            "created": record.get("created"),
            "target_created": target_created,
            "predates_target": bool(record.get("predates_target")),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "targets": apex,
            "source_data": "tldsquatting",
        },
    )


def _rollup_finding(session, apex: str, cls: str, records: list[dict]) -> Finding:
    """Build one info-severity rollup Finding for a whole benign class."""
    domains = []
    for record in records:
        risk_score, _risk_level, threat_score, threat_level, _is_apex = _score_record(record, apex)
        domains.append({
            "domain": record.get("candidate"),
            "technique": record.get("technique"),
            "reason": _REASON_BY_CLASS.get(cls, cls),
            "risk_score": risk_score,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "created": record.get("created"),
        })

    count = len(records)
    title_phrase = _TITLE_BY_CLASS.get(cls, f"{cls} lookalike domains").format(apex=apex)

    return Finding(
        session=session,
        source="tldsquatting",
        check_type=f"lookalike_{cls}",
        severity="info",
        target=apex,
        title=f"{count} {title_phrase}",
        description=(
            f"{count} registered lookalike domain(s) of {apex} were classified as "
            f"'{cls}' — {_REASON_BY_CLASS.get(cls, cls)}. No individual finding is "
            "raised for these; see extra.domains for the full list of hostnames "
            "and their individual risk/threat scores."
        ),
        remediation=(
            "No action required for this group. If a domain's DNS posture or "
            "hosted content changes in a later scan it will be reclassified, and "
            "may then surface as its own finding."
        ),
        extra={
            "count": count,
            "class": cls,
            "domains": domains,
            "source_data": "tldsquatting",
        },
    )


def analyze(session, results) -> list[Finding]:
    apex = (getattr(session, "domain", "") or "").strip().lower()

    records = [r for r in (results or []) if isinstance(r, dict) and r.get("candidate")]

    target_ns_ops = ns_operators(_first(records, "target_ns"))
    target_registrant = _first(records, "target_registrant")
    target_registrar = _first(records, "target_registrar")

    buckets: dict[str, list[dict]] = {cls: [] for cls in CLASSES}
    for record in records:
        cls = classify_lookalike(record, target_ns_ops, target_registrant, target_registrar)
        buckets[cls].append(record)

    findings: list[Finding] = [
        _individual_finding(session, apex, record) for record in buckets["threat"]
    ]

    collapse_benign = getattr(settings, "TLDSQUATTING_COLLAPSE_BENIGN", True)
    for cls in (c for c in CLASSES if c != "threat"):
        class_records = buckets[cls]
        if not class_records:
            continue
        if collapse_benign:
            findings.append(_rollup_finding(session, apex, cls, class_records))
        else:
            findings.extend(_individual_finding(session, apex, record) for record in class_records)

    return findings
