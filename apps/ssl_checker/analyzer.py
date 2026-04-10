"""SSL checker result analysis — model building layer."""

import logging

from .models import SSLFinding

logger = logging.getLogger(__name__)


def analyze(session, result: dict) -> list:
    """Build SSLFinding model instances from raw collector result."""
    domain = session.domain
    objs = []
    for v in result.get("vulnerabilities", []):
        objs.append(SSLFinding(
            session=session,
            domain=domain,
            severity=v.get("severity", "low"),
            issue_type=v.get("vulnerability_type", v.get("issue_type", "")),
            title=v.get("title", ""),
            description=v.get("description", ""),
            remediation=v.get("remediation", ""),
        ))
    return objs
