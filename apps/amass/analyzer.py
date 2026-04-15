"""Amass result analysis — builds shared Subdomain assets."""

import logging

from apps.core.assets.models import Subdomain

logger = logging.getLogger(__name__)


def analyze(session, records: list[dict]) -> list[Subdomain]:
    """Build shared Subdomain asset instances from raw collector records."""
    objs = []
    seen = set()
    for record in records:
        host = record.get("host", "").strip().lower()
        if not host or host in seen:
            continue
        seen.add(host)
        objs.append(Subdomain(
            session=session,
            domain=session.domain,
            subdomain=host,
            source="amass",
        ))
    return objs
