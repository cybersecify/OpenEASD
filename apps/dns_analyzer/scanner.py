import logging

from .models import DNSFinding

logger = logging.getLogger(__name__)


def run_dns_analysis(session) -> list:
    """Run DNS security analysis, save findings."""
    domain = session.domain
    logger.info(f"[dns_analyzer:{session.id}] Analyzing {domain}")

    try:
        from src.modules.apex_domain_security.dns_analyzer import DNSAnalyzer
        result = DNSAnalyzer().dns_record_analysis(domain)
    except Exception as e:
        logger.warning(f"[dns_analyzer:{session.id}] Failed: {e}")
        return []

    objs = []
    for v in result.get("vulnerabilities", []):
        objs.append(DNSFinding(
            session=session,
            domain=domain,
            record_type=v.get("record_type", ""),
            severity=v.get("severity", "low"),
            title=v.get("title", v.get("vulnerability_type", "")),
            description=v.get("description", ""),
            remediation=v.get("remediation", ""),
        ))

    if objs:
        DNSFinding.objects.bulk_create(objs)

    logger.info(f"[dns_analyzer:{session.id}] Found {len(objs)} DNS findings")
    return objs
