"""SSL checker data collection layer."""

import logging

logger = logging.getLogger(__name__)


def collect(session) -> dict:
    """Run SSL certificate validation and return raw result dict."""
    domain = session.domain
    logger.info(f"[ssl_checker:{session.id}] Checking {domain}")

    try:
        from src.modules.apex_domain_security.ssl_checker import SSLChecker
        return SSLChecker().ssl_certificate_validation(domain)
    except Exception as e:
        logger.warning(f"[ssl_checker:{session.id}] Failed: {e}")
        return {}
