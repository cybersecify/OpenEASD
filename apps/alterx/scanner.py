import logging

from apps.core.assets.models import Subdomain

from .analyzer import analyze
from .collector import collect

logger = logging.getLogger(__name__)


def run_alterx(session) -> list[Subdomain]:
    """Generate subdomain permutations from existing session subdomains and save them."""
    subdomains = list(
        Subdomain.objects.filter(session=session)
        .values_list("subdomain", flat=True)
        .distinct()
    )

    if not subdomains:
        logger.info("[alterx:%s] no subdomains to permute", session.id)
        return []

    raw = collect(subdomains)
    objs = analyze(session, raw)

    if objs:
        Subdomain.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(Subdomain.objects.filter(session=session, source="alterx"))
    logger.info("[alterx:%s] saved %d permutation subdomains", session.id, len(saved))
    return saved
