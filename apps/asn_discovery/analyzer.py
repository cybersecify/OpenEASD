"""ASN discovery analyzer — turns amass intel records into informational Findings.

One ``severity="info"`` Finding per discovered ASN, carrying its CIDR netblocks.
The value is inventory: these ranges can host internet-facing infrastructure that
has *no DNS record* pointing at it, so it never shows up in subdomain enumeration.
Surfacing the owned ranges lets an operator decide, out of band, whether to bring
them into scope.

SAFE SCOPE: this tool only *reports* the ranges. It deliberately does NOT feed the
CIDRs into naabu/nmap or any active scan — doing so would send packets to hosts
that may fall outside the scan's DomainAuthorization. Expanding active scanning to
these ranges is a separate, explicit authorization decision and is intentionally
left as a follow-up (not in this change).
"""

import logging

from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)


def analyze(session, records: list[dict]) -> list[Finding]:
    """Build one informational Finding per ASN record."""
    if not records:
        return []

    findings: list[Finding] = []
    seen: set[int] = set()

    for record in records:
        asn = record.get("asn")
        if asn is None or asn in seen:
            continue
        seen.add(asn)

        description = (record.get("description") or "").strip()
        cidrs = [c for c in record.get("cidrs", []) if c]
        cidr_count = len(cidrs)

        org_label = f" — {description}" if description else ""
        cidr_summary = (
            f"{cidr_count} CIDR block(s): {', '.join(cidrs)}"
            if cidrs else "no CIDR blocks announced"
        )
        title_count = (
            f"{cidr_count} CIDR block{'s' if cidr_count != 1 else ''}"
            if cidrs else "no CIDR blocks"
        )

        findings.append(Finding(
            session=session,
            source="asn_discovery",
            check_type="asn",
            severity="info",
            title=f"Organization owns ASN {asn} ({title_count})",
            description=(
                f"AS{asn}{org_label} is registered to the organization behind "
                f"{session.domain}. It announces {cidr_summary}. IP ranges owned "
                f"directly by the organization can host internet-facing services "
                f"that have no DNS record, so they are invisible to subdomain "
                f"enumeration. This finding is informational — it inventories the "
                f"owned address space so you can decide, separately, whether to "
                f"bring it into active scan scope."
            ),
            remediation=(
                "Review each netblock against your asset inventory. Confirm every "
                "range is still allocated to you and that anything live on it is "
                "intended to be internet-facing. To actively scan these ranges, "
                "add them to scope under an explicit authorization — OpenEASD does "
                "not auto-expand port scanning to discovered CIDRs."
            ),
            target=f"AS{asn}",
            extra={
                "asn": asn,
                "asn_description": description,
                "cidrs": cidrs,
                "cidr_count": cidr_count,
            },
        ))

    logger.info(
        "[asn_discovery:%s] %d ASN record(s) → %d finding(s)",
        session.id, len(records), len(findings),
    )
    return findings
