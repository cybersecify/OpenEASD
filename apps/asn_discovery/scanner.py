"""ASN discovery scanner — thin orchestrator: collect → analyze → save.

Runs ``amass intel`` (passive registry / BGP reconnaissance) to inventory the
ASNs and CIDR ranges owned by the organization behind the domain, then writes one
informational Finding per ASN.

The scan-entry DomainAuthorization gate (apps/core/scans/api.py +
apps/core/scheduler/scheduler.py) already governs whether this tool runs — same
as naabu/nmap, no per-tool re-check. Discovered CIDRs are reported only; they are
deliberately NOT fed into any active port/service scan here (that expansion is a
separate authorization decision — see collector.py / analyzer.py).
"""

import logging

from apps.core.findings.models import Finding

from .analyzer import analyze
from .collector import collect

logger = logging.getLogger(__name__)


def run_asn_discovery(session) -> list[Finding]:
    """Discover owned ASNs/CIDRs for the session domain and persist Findings."""
    records = collect(session)
    if not records:
        return []

    findings = analyze(session, records)
    if not findings:
        return []

    Finding.objects.bulk_create(findings, ignore_conflicts=True)

    saved = list(Finding.objects.filter(session=session, source="asn_discovery"))
    logger.info("[asn_discovery:%s] saved %d ASN finding(s)", session.id, len(saved))
    return saved
