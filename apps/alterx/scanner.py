import logging
import secrets

import dns.exception
import dns.resolver

from apps.core.assets.models import Subdomain

from .analyzer import analyze
from .collector import collect

logger = logging.getLogger(__name__)


def _has_wildcard_dns(domain: str) -> bool:
    """Return True if domain answers wildcard queries (any random hostname resolves).

    Cloudflare and similar CDNs respond to *.domain — so alterx permutations
    all resolve even though the subdomains don't exist. When detected, the
    scanner skips alterx to avoid flooding the pipeline with fake hosts.
    """
    probe = f"openeasd-wc-{secrets.token_hex(6)}.{domain}"
    try:
        dns.resolver.resolve(probe, "A")
        return True
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.exception.Timeout,
        dns.exception.DNSException,
    ):
        return False


def run_alterx(session) -> list[Subdomain]:
    subdomains = list(
        Subdomain.objects.filter(session=session)
        .values_list("subdomain", flat=True)
        .distinct()
    )

    if not subdomains:
        logger.info(f"[alterx:{session.id}] no subdomains to permute")
        return []

    if _has_wildcard_dns(session.domain):
        logger.warning(
            "[alterx:%s] wildcard DNS detected for %s — skipping permutations "
            "(random hostname resolved; all alterx results would be false positives)",
            session.id,
            session.domain,
        )
        return []

    raw = collect(subdomains)
    objs = analyze(session, raw)

    if objs:
        Subdomain.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(Subdomain.objects.filter(session=session, source="alterx"))
    logger.info(f"[alterx:{session.id}] saved {len(saved)} permutation subdomains")
    return saved
