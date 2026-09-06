"""Historical-DNS analyzer — one informational Finding per historical record.

Each A/AAAA/MX record the domain has ever resolved to is surfaced as an
`info` Finding: stale/forgotten records point at infrastructure that may no
longer be under the owner's control (old hosting, decommissioned mail servers)
— useful recon context and an occasional takeover lead.
"""

import logging

from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)

_ATTRIBUTION = "Source: passive DNS"


def analyze(session, domain: str, records: list[dict]) -> list[Finding]:
    """Build one info Finding per historical record. Returns [] when none."""
    if not records:
        return []

    findings: list[Finding] = []
    for rec in records:
        rtype = rec.get("type", "")
        value = rec.get("value", "")
        if not rtype or not value:
            continue

        seen = ""
        if rec.get("first_seen") or rec.get("last_seen"):
            seen = f" (seen {rec.get('first_seen') or '?'} → {rec.get('last_seen') or '?'})"

        findings.append(Finding(
            session=session,
            source="dns_history",
            check_type="dns_history",
            severity="info",
            title=f"Historical DNS {rtype} record: {value}",
            description=(
                f"{domain} has historically resolved via a {rtype} record to "
                f"{value}{seen}. Historical records reveal past hosting and mail "
                f"infrastructure; a record pointing at infrastructure no longer "
                f"under your control can be a takeover or spoofing lead. "
                f"{_ATTRIBUTION}."
            ),
            remediation=(
                f"Confirm {value} is still owned/controlled by you. If it is a "
                f"decommissioned host or provider, ensure the resource is fully "
                f"released and no live DNS still points at it."
            ),
            target=domain,
            extra={
                "record_type": rtype,
                "value": value,
                "first_seen": rec.get("first_seen", ""),
                "last_seen": rec.get("last_seen", ""),
            },
        ))

    logger.info("dns_history: built %d historical-record findings", len(findings))
    return findings
