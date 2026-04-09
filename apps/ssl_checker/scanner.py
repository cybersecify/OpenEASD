import logging

from .models import SSLFinding

logger = logging.getLogger(__name__)


def run_ssl_check(session) -> list:
    """Run SSL/TLS certificate validation, save findings."""
    domain = session.domain
    logger.info(f"[ssl_checker:{session.id}] Checking {domain}")

    try:
        from src.modules.apex_domain_security.ssl_checker import SSLChecker
        result = SSLChecker().ssl_certificate_validation(domain)
    except Exception as e:
        logger.warning(f"[ssl_checker:{session.id}] Failed: {e}")
        return []

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

    if objs:
        SSLFinding.objects.bulk_create(objs)

    logger.info(f"[ssl_checker:{session.id}] Found {len(objs)} SSL findings")
    return objs
