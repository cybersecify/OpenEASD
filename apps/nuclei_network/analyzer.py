"""Nuclei network analyzer — maps raw nuclei JSON to unified Finding model.

Same parsing logic as apps/nuclei/analyzer.py but with source="nuclei_network"
and Port FK linking instead of URL FK.
"""

import logging

from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def _parse_cve_ids(classification: dict) -> list[str]:
    cve_raw = classification.get("cve-id") or []
    if isinstance(cve_raw, str):
        return [cve_raw] if cve_raw else []
    if isinstance(cve_raw, list):
        return [c for c in cve_raw if c]
    return []


def analyze(session, records: list[dict]) -> list[Finding]:
    """Build Finding objects from nuclei network scan results."""
    if not records:
        return []

    from apps.core.assets.models import Port

    # Build (address, port) → Port lookup
    port_map = {
        (p.address, p.port): p
        for p in Port.objects.filter(session=session)
    }

    seen: set[tuple[str, str]] = set()
    findings: list[Finding] = []

    for data in records:
        template_id = data.get("template-id") or data.get("templateID") or ""
        matched_at = data.get("matched-at") or data.get("host") or ""
        dedup_key = (template_id, matched_at)

        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        info = data.get("info", {})
        classification = info.get("classification") or {}
        raw_severity = (info.get("severity") or "info").lower()
        severity = _SEVERITY_MAP.get(raw_severity, "info")

        template_name = info.get("name") or template_id
        cve_ids = _parse_cve_ids(classification)
        cvss_score = classification.get("cvss-score")
        check_type = "cve" if cve_ids else "network"

        title = f"{cve_ids[0]}: {template_name}" if cve_ids else template_name
        if len(title) > 250:
            title = title[:247] + "..."

        # Link to Port FK via matched_at (format: IP:port)
        port_fk = None
        target = matched_at
        if ":" in matched_at:
            parts = matched_at.rsplit(":", 1)
            try:
                port_fk = port_map.get((parts[0], int(parts[1])))
            except (ValueError, IndexError):
                pass

        findings.append(Finding(
            session=session,
            source="nuclei_network",
            check_type=check_type,
            severity=severity,
            title=title,
            description=info.get("description", ""),
            remediation=info.get("remediation", ""),
            port=port_fk,
            target=target,
            extra={
                "template_id": template_id,
                "template_name": template_name,
                "matched_at": matched_at,
                "matcher_name": data.get("matcher-name", ""),
                "cve_ids": cve_ids,
                "cvss_score": cvss_score,
                "extracted_results": data.get("extracted-results", []),
            },
        ))

    logger.info(
        f"[nuclei_network:{session.id}] {len(findings)} findings "
        f"({len(records) - len(findings)} duplicates removed)"
    )
    return findings
