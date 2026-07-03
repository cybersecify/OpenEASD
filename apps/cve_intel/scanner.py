"""CVE Intel scanner — enriches CVE findings with EPSS + CISA KEV in place.

Phase 12 (Prioritization). Runs after every CVE-producing tool so it can enrich
nmap, nuclei, and nuclei_network findings in a single pass:
  gather CVEs -> one KEV lookup + one bulk EPSS query -> write rollup into extra.

Never raises on network failure — a scan must complete even if the intel feeds
are down; findings are simply left unenriched.
"""

import logging

from apps.core.findings.models import Finding

from .analyzer import build_finding_intel, finding_cves
from .collector import fetch_epss_scores, fetch_kev_catalog

logger = logging.getLogger(__name__)


def run_cve_intel(session) -> list[Finding]:
    """Enrich this session's CVE findings. Returns the findings that were updated."""
    # Fetch all findings and filter CVEs in Python — avoids SQLite JSON-lookup
    # quirks and the per-session set is small (dozens of rows).
    findings = list(Finding.objects.filter(session=session))
    cve_by_finding = {f: finding_cves(f) for f in findings}
    cve_by_finding = {f: c for f, c in cve_by_finding.items() if c}

    if not cve_by_finding:
        logger.info("[cve_intel:%s] no CVE findings to enrich", session.id)
        return []

    all_cves = sorted({c for cves in cve_by_finding.values() for c in cves})
    logger.info(
        "[cve_intel:%s] enriching %d findings across %d unique CVEs",
        session.id, len(cve_by_finding), len(all_cves),
    )

    kev = fetch_kev_catalog()
    epss = fetch_epss_scores(all_cves)

    if not kev and not epss:
        logger.warning("[cve_intel:%s] no intel available (feeds down) — skipping", session.id)
        return []

    updated: list[Finding] = []
    for finding, cves in cve_by_finding.items():
        intel = build_finding_intel(cves, kev, epss)
        if not intel:
            continue
        extra = finding.extra or {}
        extra.update(intel)
        finding.extra = extra
        updated.append(finding)

    if updated:
        Finding.objects.bulk_update(updated, ["extra"])

    kev_count = sum(1 for f in updated if (f.extra or {}).get("cisa_kev"))
    logger.info(
        "[cve_intel:%s] enriched %d findings (%d flagged CISA KEV)",
        session.id, len(updated), kev_count,
    )
    return updated
