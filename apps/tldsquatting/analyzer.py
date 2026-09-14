"""tldsquatting analyzer — turns registered-lookalike records into shared Findings.

One Finding per registered lookalike domain (``check_type="lookalike_domain"`` —
the same check_type the former typosquat tool used, so ``asn_cluster`` consumes
these findings unchanged). Severity is no longer an ad-hoc ladder: it is the
band of a ported two-stage score (``scoring.py``):

  * ``calculate_risk_score`` scores registration timing + DNS posture. Its
    dominant rule is **PRE-EXISTING** — a lookalike that IS the apex or was
    registered *before* the target (the ``amnic.net`` case) scores 0.0 and is
    reported as ``info`` (it cannot be impersonating a domain younger than it).
  * ``calculate_threat_score`` adds live weaponization signals (login form,
    brand mentions, parked) from the homepage probe.

The final **threat level** maps to Finding severity:
``PRE-EXISTING→info, LOW→low, MEDIUM→medium, HIGH→high, CRITICAL→critical``.
The numeric scores + levels + creation dates land in ``extra`` so a defender
(and the report / AI triage) can see exactly what drove the rating.
"""

import logging

from apps.core.data.findings.models import Finding

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


def analyze(session, results) -> list[Finding]:
    findings: list[Finding] = []
    apex = (getattr(session, "domain", "") or "").strip().lower()

    for record in results or []:
        if not isinstance(record, dict):
            continue
        candidate = record.get("candidate")
        if not candidate:
            continue

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

        severity = _SEVERITY_BY_LEVEL.get(threat_level, "low")
        summary = _record_summary(record)
        drivers = _drivers(record, apex, threat_level)

        findings.append(Finding(
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
        ))

    return findings
