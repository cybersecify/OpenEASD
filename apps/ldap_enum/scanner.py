"""Run LDAP root DSE metadata checks on authorized, classified LDAP ports."""

import logging

from apps.core.data.findings.models import Finding

from .analyzer import analyze
from .collector import collect

logger = logging.getLogger(__name__)


def run_ldap_enum(session) -> list[Finding]:
    """Save informational findings from a read-only, unauthenticated check."""
    responses = collect(session)
    findings = analyze(session, responses)
    if findings:
        Finding.objects.bulk_create(findings)
    logger.info("[ldap_enum:%s] %d metadata findings", session.id, len(findings))
    return findings
