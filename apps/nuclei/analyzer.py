"""Nuclei result analysis — model building layer."""

import logging

from .models import NucleiFinding

logger = logging.getLogger(__name__)

SEVERITY_MAP = {"info": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}


def analyze(session, records: list[dict]) -> list:
    """Build NucleiFinding model instances from raw collector records."""
    objs = []
    for data in records:
        info = data.get("info", {})
        raw_severity = info.get("severity", "info")
        severity = SEVERITY_MAP.get(raw_severity, "low")
        classification = info.get("classification", {})
        objs.append(NucleiFinding(
            session=session,
            host=data.get("host", ""),
            template_id=data.get("template-id", data.get("templateID", "")),
            template_name=info.get("name", ""),
            severity=severity,
            description=info.get("description", ""),
            matched_at=data.get("matched-at", ""),
            cvss_score=classification.get("cvss-score"),
            cve_id=", ".join(classification.get("cve-id", [])) if isinstance(classification.get("cve-id"), list) else "",
        ))
    return objs
