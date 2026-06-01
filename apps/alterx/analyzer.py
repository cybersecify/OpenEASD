import logging
import re

from apps.core.assets.models import Subdomain

logger = logging.getLogger(__name__)

_VALID_HOSTNAME = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def analyze(session, raw: list[str]) -> list[Subdomain]:
    """Normalize permutations, deduplicate, return Subdomain objects ready for bulk_create."""
    if not raw:
        return []

    existing = set(
        Subdomain.objects.filter(session=session)
        .values_list("subdomain", flat=True)
    )

    objs: list[Subdomain] = []
    seen: set[str] = set()

    for line in raw:
        host = line.strip().lower()
        if not host or not _VALID_HOSTNAME.match(host):
            continue
        if host in seen or host in existing:
            continue
        seen.add(host)
        objs.append(Subdomain(
            session=session,
            domain=session.domain,
            subdomain=host,
            source="alterx",
        ))

    logger.info(
        "[alterx:%s] %d raw permutations → %d new subdomains",
        session.id, len(raw), len(objs),
    )
    return objs
