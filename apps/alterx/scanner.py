import logging

from apps.core.assets.models import Subdomain

from .analyzer import analyze
from .collector import collect

logger = logging.getLogger(__name__)


def run_alterx(session) -> list[Subdomain]:
    subdomains = list(
        Subdomain.objects.filter(session=session)
        .values_list("subdomain", flat=True)
        .distinct()
    )

    if not subdomains:
        logger.info(f"[alterx:{session.id}] no subdomains to permute")
        return []

    raw = collect(subdomains)
    objs = analyze(session, raw)

    if objs:
        Subdomain.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(Subdomain.objects.filter(session=session, source="alterx"))
    logger.info(f"[alterx:{session.id}] saved {len(saved)} permutation subdomains")
    return saved
