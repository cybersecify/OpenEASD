"""Subfinder result analysis — model building layer."""

import logging

from .models import Subdomain

logger = logging.getLogger(__name__)


def analyze(session, records: list[dict]) -> list:
    """Build Subdomain model instances from raw collector records."""
    objs = []
    for record in records:
        host = record.get("host", "").strip()
        if host:
            objs.append(Subdomain(
                session=session,
                subdomain=host,
                ip_address=record.get("ip") or None,
            ))
    return objs
