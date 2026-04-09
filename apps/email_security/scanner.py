import logging

from .models import EmailFinding

logger = logging.getLogger(__name__)


def run_email_check(session) -> list:
    """Run SPF/DMARC email security checks, save findings."""
    domain = session.domain
    logger.info(f"[email_security:{session.id}] Checking {domain}")

    try:
        from src.modules.apex_domain_security.email_security import EmailSecurity
        result = EmailSecurity().spf_dmarc_checker(domain)
    except Exception as e:
        logger.warning(f"[email_security:{session.id}] Failed: {e}")
        return []

    objs = []
    for v in result.get("vulnerabilities", []):
        objs.append(EmailFinding(
            session=session,
            domain=domain,
            check_type=v.get("check_type", v.get("vulnerability_type", "")),
            severity=v.get("severity", "low"),
            title=v.get("title", ""),
            description=v.get("description", ""),
            remediation=v.get("remediation", ""),
        ))

    if objs:
        EmailFinding.objects.bulk_create(objs)

    logger.info(f"[email_security:{session.id}] Found {len(objs)} email security findings")
    return objs
