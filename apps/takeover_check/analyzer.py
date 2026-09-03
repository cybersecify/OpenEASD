"""Takeover analyzer — converts subzy records into Finding objects.

subzy emits one record per probed subdomain. The exact JSON schema is upstream
and may drift; we look up keys defensively and skip records that don't carry
a vulnerable subdomain + an identifiable service fingerprint.
"""

import logging
import urllib.request

from apps.core.assets.models import Subdomain
from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)


def _is_live(subdomain: str, timeout: int = 8) -> bool:
    """Return True if the subdomain serves real content (HTTP < 400).

    A live subdomain cannot be taken over — the resource is already claimed.
    We probe HTTPS first, then HTTP, so CDN-terminated and plain-HTTP sites
    both get caught.
    """
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(
                f"{scheme}://{subdomain}/",
                headers={"User-Agent": "OpenEASD/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status < 400
        except Exception:
            continue
    return False


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
        if service == "unknown":
            # subzy flagged vulnerable but couldn't identify the hosting service.
            # Probe the subdomain — if it serves real content it's a live site,
            # not a dangling CNAME, so suppress the finding.
            if _is_live(subdomain_name):
                logger.info(
                    "[takeover_check:%s] Skipping %s — subzy flagged vulnerable "
                    "but HTTP probe returned live content (false positive)",
                    session.id,
                    subdomain_name,
                )
                continue
            logger.warning(
                "[takeover_check:%s] %s — no service fingerprint and not live, "
                "reporting for manual verification",
                session.id,
                subdomain_name,
            )

        subdomain_fk = subdomain_index.get(subdomain_name)
        unidentified = service == "unknown"
        service_label = "an unidentified service" if unidentified else service
        extra_note = (
            " subzy flagged this as vulnerable but could not identify the hosting "
            "service and the subdomain did not return live content — verify manually."
            if unidentified else ""
        )

        findings.append(Finding(
            session=session,
            source="takeover_check",
            check_type="subdomain_takeover",
            severity="high",
            title=f"Subdomain takeover possible: {subdomain_name} ({service_label})",
            description=(
                f"{subdomain_name} appears to point at an unclaimed {service_label} "
                f"resource. An attacker who registers that resource on the "
                f"hosting service could serve arbitrary content under your "
                f"subdomain — credential phishing, malware delivery, or SSO-cookie "
                f"theft from same-eTLD context." + extra_note
            ),
            remediation=(
                "Either remove the dangling DNS record or reclaim the unused "
                f"resource on {service_label}. Verify by manually visiting the subdomain — "
                "a stale CNAME with an unclaimed third-party target is the "
                "signature pattern."
            ),
            subdomain=subdomain_fk,
            target=subdomain_name,
            extra={
                "service": service_label,
                "raw": record,
            },
        ))

    logger.info(
        "[takeover_check:%s] subzy records=%d → vulnerable findings=%d",
        session.id, len(records), len(findings),
    )
    return findings
