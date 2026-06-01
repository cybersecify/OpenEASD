"""Subdomain takeover analyzer — parse subzy results and create Finding records."""

import logging

from apps.core.assets.models import Subdomain
from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)

# Severity mapping for takeover vulnerabilities
SEVERITY = "high"


def analyze(session, records: list[dict]) -> list[Finding]:
    """
    Parse subzy results and create Finding records.

    Args:
        session: The scan session object
        records: List of subzy result records

    Returns:
        List of Finding model instances
    """
    if not records:
        return []

    # Get subdomains for this session
    subdomains = {
        s.subdomain: s
        for s in Subdomain.objects.filter(session=session)
    }

    objs = []

    for record in records:
        try:
            subdomain_str = record.get("subdomain", "")
            if not subdomain_str:
                continue

            # Find matching subdomain record
            subdomain = subdomains.get(subdomain_str)
            if not subdomain:
                continue

            # Extract details
            platform = record.get("platform", "unknown")
            cname = record.get("cname", "")
            status_code = record.get("status_code", "")
            vulnerable = record.get("vulnerable", False)

            if not vulnerable:
                continue

            # Create Finding
            obj = Finding(
                session=session,
                subdomain=subdomain,
                source="takeover_check",
                check_type="subdomain_takeover",
                severity=SEVERITY,
                title=f"Subdomain takeover vulnerability: {subdomain_str}",
                description=(
                    f"Subdomain {subdomain_str} is vulnerable to takeover.\n\n"
                    f"Platform: {platform}\n"
                    f"CNAME: {cname}\n"
                    f"HTTP Status: {status_code}\n\n"
                    f"The subdomain points to an unclaimed {platform} resource. "
                    f"An attacker could register this resource and serve content "
                    f"as {subdomain_str}."
                ),
                extras={
                    "platform": platform,
                    "cname": cname,
                    "status_code": status_code,
                    "subdomain": subdomain_str,
                },
            )
            objs.append(obj)

        except Exception as e:
            logger.warning(f"Failed to process subzy record: {e}")
            continue

    logger.info(
        f"[takeover_check:{session.id}] "
        f"Analyzed {len(records)} records → {len(objs)} findings"
    )

    return objs
