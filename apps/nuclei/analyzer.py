"""Nuclei result analysis — maps raw nuclei JSON to unified Finding model.

Nuclei JSON output format (per finding):
{
  "template-id": "tech-detect",
  "info": {
    "name": "Technology Detection",
    "severity": "info",
    "description": "...",
    "classification": {
      "cvss-score": 7.5,
      "cve-id": ["CVE-2021-12345"]
    },
    "remediation": "..."
  },
  "host": "https://example.com",
  "matched-at": "https://example.com/path",
  "matcher-name": "wordpress",
  "extracted-results": ["4.9.1"],
  "curl-command": "curl -X GET ..."
}
"""

import logging

from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)

# Map nuclei severity to unified Finding severity
_SEVERITY_MAP = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def _parse_host_target(data: dict) -> str:
    """Extract a clean target string from nuclei record."""
    return data.get("matched-at", "") or data.get("host", "")


def _parse_cve_ids(classification: dict) -> list[str]:
    """Extract CVE IDs from nuclei classification, handling list or string."""
    cve_raw = classification.get("cve-id") or []
    if isinstance(cve_raw, str):
        return [cve_raw] if cve_raw else []
    if isinstance(cve_raw, list):
        return [c for c in cve_raw if c]
    return []


def _build_finding(session, data: dict, url_fk=None) -> Finding:
    """Build a single Finding from a nuclei JSON record."""
    info = data.get("info", {})
    classification = info.get("classification") or {}
    raw_severity = (info.get("severity") or "info").lower()
    severity = _SEVERITY_MAP.get(raw_severity, "info")

    template_id = data.get("template-id") or data.get("templateID") or ""
    template_name = info.get("name") or template_id
    description = info.get("description") or ""
    remediation = info.get("remediation") or ""
    target = _parse_host_target(data)

    cve_ids = _parse_cve_ids(classification)
    cvss_score = classification.get("cvss-score")
    check_type = "cve" if cve_ids else "web"

    # Build title
    if cve_ids:
        title = f"{cve_ids[0]}: {template_name}"
    else:
        title = template_name
    # Truncate title to fit CharField
    if len(title) > 250:
        title = title[:247] + "..."

    return Finding(
        session=session,
        source="nuclei",
        check_type=check_type,
        severity=severity,
        title=title,
        description=description,
        remediation=remediation,
        url=url_fk,
        target=target,
        extra={
            "template_id": template_id,
            "template_name": template_name,
            "matched_at": data.get("matched-at", ""),
            "matcher_name": data.get("matcher-name", ""),
            "cve_ids": cve_ids,
            "cvss_score": cvss_score,
            "curl_command": data.get("curl-command", ""),
            "extracted_results": data.get("extracted-results", []),
        },
    )


def analyze(session, records: list[dict]) -> list[Finding]:
    """
    Build Finding objects from raw nuclei JSON records.

    Links findings to URL objects where possible (matched by host URL).
    Deduplicates by (template_id, matched_at) — nuclei can report the
    same finding multiple times across template runs.
    """
    from apps.core.assets.models import URL

    if not records:
        return []

    # Build URL lookup: url string → URL object
    url_map: dict[str, object] = {}
    for url_obj in URL.objects.filter(session=session):
        url_map[url_obj.url] = url_obj

    seen: set[tuple[str, str]] = set()
    findings: list[Finding] = []

    for data in records:
        template_id = data.get("template-id") or data.get("templateID") or ""
        matched_at = data.get("matched-at") or data.get("host") or ""
        dedup_key = (template_id, matched_at)

        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        # Try to link to a URL object
        host_url = data.get("host", "")
        url_fk = url_map.get(host_url)

        findings.append(_build_finding(session, data, url_fk))

    logger.info(
        f"[nuclei:{session.id}] {len(findings)} findings "
        f"({len(records) - len(findings)} duplicates removed)"
    )
    return findings
