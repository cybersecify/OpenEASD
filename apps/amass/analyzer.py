"""Amass result analysis — builds shared Subdomain assets."""

import logging

from apps.core.assets.models import Subdomain

logger = logging.getLogger(__name__)


def _in_scope(host: str, domain: str) -> bool:
    host = host.lower()
    domain = domain.lower()
    return host == domain or host.endswith("." + domain)


def analyze(session, records: list[dict]) -> list[Subdomain]:
    """Build shared Subdomain asset instances from raw collector records."""
    objs = []
    seen = set()
    dropped = 0
    for record in records:
        host = record.get("host", "").strip().lower()
        if not host or host in seen:
            continue
        if not _in_scope(host, session.domain):
            dropped += 1
            continue
        seen.add(host)
        objs.append(Subdomain(
            session=session,
            domain=session.domain,
            subdomain=host,
            source="amass",
        ))
    if dropped:
        logger.info("[amass:%s] dropped %d out-of-scope subdomains", session.id, dropped)
    return objs
