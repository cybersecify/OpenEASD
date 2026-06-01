"""Takeover analyzer — converts subzy records into Finding objects.

subzy emits one record per probed subdomain. The exact JSON schema is upstream
and may drift; we look up keys defensively and skip records that don't carry
a vulnerable subdomain + an identifiable service fingerprint.
"""

import logging

from apps.core.assets.models import Subdomain
from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)


def _is_vulnerable(record: dict) -> bool:
    """Treat a record as vulnerable if any common subzy boolean signals it.

    subzy versions have used both ``vulnerable`` and ``vuln`` keys; some forks
    emit ``status: VULNERABLE``. Be tolerant.
    """
    for key in ("vulnerable", "vuln"):
        value = record.get(key)
        if isinstance(value, bool) and value:
            return True
        if isinstance(value, str) and value.lower() in {"true", "vulnerable"}:
            return True
    status = record.get("status")
    if isinstance(status, str) and "vuln" in status.lower():
        return True
    return False


def _subdomain_of(record: dict) -> str:
    for key in ("subdomain", "target", "host", "url"):
        value = record.get(key)
        if value:
            return str(value).strip()
    return ""


def _service_of(record: dict) -> str:
    for key in ("service", "platform", "engine", "provider"):
        value = record.get(key)
        if value:
            return str(value)
    return "unknown"


def analyze(session, records: list[dict]) -> list[Finding]:
    """Build Finding objects from subzy records for the given session.

    Each vulnerable subdomain becomes one ``severity="high"`` finding linked
    to its existing Subdomain row (if present in the session) plus the raw
    subzy record in ``extra``.
    """
    if not records:
        return []

    subdomain_index = {
        s.subdomain: s
        for s in Subdomain.objects.filter(session=session)
    }

    findings: list[Finding] = []
    seen: set[str] = set()

    for record in records:
        if not _is_vulnerable(record):
            continue

        subdomain_name = _subdomain_of(record)
        if not subdomain_name or subdomain_name in seen:
            continue
        seen.add(subdomain_name)

        service = _service_of(record)
        subdomain_fk = subdomain_index.get(subdomain_name)

        findings.append(Finding(
            session=session,
            source="takeover_check",
            check_type="subdomain_takeover",
            severity="high",
            title=f"Subdomain takeover possible: {subdomain_name} ({service})",
            description=(
                f"{subdomain_name} appears to point at an unclaimed {service} "
                f"resource. An attacker who registers that resource on the "
                f"hosting service could serve arbitrary content under your "
                f"subdomain — credential phishing, malware delivery, or SSO-cookie "
                f"theft from same-eTLD context."
            ),
            remediation=(
                "Either remove the dangling DNS record or reclaim the unused "
                f"resource on {service}. Verify by manually visiting the subdomain — "
                "a stale CNAME with an unclaimed third-party target is the "
                "signature pattern."
            ),
            subdomain=subdomain_fk,
            target=subdomain_name,
            extra={
                "service": service,
                "raw": record,
            },
        ))

    logger.info(
        "[takeover_check:%s] subzy records=%d → vulnerable findings=%d",
        session.id, len(records), len(findings),
    )
    return findings
