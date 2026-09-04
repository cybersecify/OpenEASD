"""Breach-exposure analyzer — builds a single aggregate breach Finding.

Privacy contract (hard requirement): this tool must NEVER store or display
plaintext credentials or individual email addresses. Only aggregate counts and
PUBLIC breach metadata (breach names, years, record totals) are persisted. The
collector already discards any per-account/alias data; this analyzer only ever
reads the aggregate fields below, so no credential/email field can reach a
Finding even if a source response carried one.
"""

import datetime
import logging

from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)

_MAX_BREACHES_SHOWN = 20  # cap the breach-name list stored / shown
_LARGE_ACCOUNT_THRESHOLD = 100  # HIBP: many affected accounts -> escalate
_RECENT_YEARS = 3  # a breach within N years -> creds likely still live -> escalate

_ATTRIBUTION = {
    "hibp": "Source: Have I Been Pwned (breacheddomain)",
    "xposedornot": "Source: XposedOrNot (public breach catalog)",
}


def _has_recent_breach(breaches: list) -> bool:
    this_year = datetime.date.today().year
    for b in breaches:
        year = str(b.get("year") or "")
        if year.isdigit() and (this_year - int(year)) <= _RECENT_YEARS:
            return True
    return False


def analyze(session, domain: str, data: dict) -> list[Finding]:
    breach_count = int(data.get("breach_count") or 0)

    # No exposure -> no finding.
    if breach_count == 0:
        logger.info("breach_check: %s has no known breach exposure — no finding", domain)
        return []

    tier = data.get("tier") or "xposedornot"
    accounts = int(data.get("accounts") or 0)
    breaches = [b for b in (data.get("breaches") or []) if isinstance(b, dict)]
    names = [str(b.get("name")) for b in breaches if b.get("name")][:_MAX_BREACHES_SHOWN]

    # Severity: escalate to high on a large affected-account count (authoritative
    # HIBP signal) or a recent breach (credentials likely still valid / reused);
    # otherwise medium. Breach exposure is never merely informational — reused
    # credentials are a live credential-stuffing risk.
    recent = _has_recent_breach(breaches)
    severity = "high" if (accounts >= _LARGE_ACCOUNT_THRESHOLD or recent) else "medium"

    if accounts > 0:
        title = (
            f"Breach exposure: {accounts} account(s) across {breach_count} known "
            f"breach(es) for {domain}"
        )
    else:
        title = f"{domain} appears in {breach_count} known data breach(es)"

    lines = [
        f"Third-party breach data associates {domain} with {breach_count} known "
        f"data breach(es). Credentials exposed in these breaches are commonly "
        f"reused and fuel credential-stuffing and account-takeover attempts "
        f"against your own systems.",
        "",
        f"Known breaches associated: {breach_count}",
    ]
    if accounts > 0:
        lines.append(f"Affected accounts on this domain: {accounts}")
    if names:
        lines.append("")
        lines.append("Breaches (public metadata):")
        for b in breaches[:_MAX_BREACHES_SHOWN]:
            year = b.get("year")
            records = int(b.get("records") or 0)
            suffix = []
            if year:
                suffix.append(str(year))
            if records:
                suffix.append(f"{records:,} records")
            tail = f" ({', '.join(suffix)})" if suffix else ""
            lines.append(f"  - {b.get('name')}{tail}")
    lines.append("")
    lines.append(
        "These are aggregate counts and public breach metadata only — no "
        "plaintext credentials or individual email addresses are stored or shown "
        "here. Identifying the specific affected accounts requires your own "
        "follow-up with the breach data provider."
    )
    lines.append(_ATTRIBUTION.get(tier, _ATTRIBUTION["xposedornot"]))

    remediation = (
        "Force a credential reset for accounts on this domain and enforce MFA "
        "everywhere. Enrol the domain in continuous breach monitoring, block "
        "known-breached passwords at sign-up / reset, and educate users against "
        "password reuse across services."
    )

    finding = Finding(
        session=session,
        source="breach_check",
        check_type="breach_exposure",
        severity=severity,
        title=title,
        description="\n".join(lines),
        remediation=remediation,
        target=domain,
        extra={
            "tier": tier,
            "accounts": accounts,
            "breach_count": breach_count,
            "breaches": names,  # names only — public metadata, no PII
            "recent_breach": recent,
        },
    )
    return [finding]
