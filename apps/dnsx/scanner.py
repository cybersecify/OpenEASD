"""dnsx scanner — orchestrator: collect → analyze → save."""

import logging

from django.utils import timezone as django_tz

from apps.core.assets.models import IPAddress, Subdomain
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_dnsx(session) -> list:
    """Resolve all subdomains for the session, save public IPs, mark active subdomains.

    Returns list of active Subdomain instances after dnsx finishes.
    """
    # Pull all subdomains discovered for this session (from subfinder etc.)
    subs = list(Subdomain.objects.filter(session=session))
    if not subs:
        logger.info(f"[dnsx:{session.id}] No subdomains to resolve")
        return []

    subdomain_names = [s.subdomain for s in subs]
    subdomain_index = {s.subdomain: s for s in subs}

    records = collect(session, subdomain_names)
    ip_objs, activated = analyze(session, records, subdomain_index)

    if ip_objs:
        IPAddress.objects.bulk_create(ip_objs, ignore_conflicts=True)

    if activated:
        now = django_tz.now()
        for sub in activated:
            sub.is_active = True
            sub.resolved_at = now
        Subdomain.objects.bulk_update(activated, ["is_active", "resolved_at"])

    # Prune dead alterx permutation candidates. alterx INVENTS subdomain names
    # (dev-api.example.com, api-staging.example.com, …); a candidate that doesn't
    # resolve isn't a real subdomain and must not inflate the surface count — a
    # cybersecify.com run generated 1,858 alterx candidates of which only 1 was
    # real, showing "1,862 subdomains" for a 5-subdomain surface. Names from the
    # discovery tools (subfinder/amass) are kept even if unresolved: those are
    # real observed names, not guesses.
    pruned, _ = (
        Subdomain.objects.filter(session=session, source="alterx", is_active=False)
        .delete()
    )
    if pruned:
        logger.info(f"[dnsx:{session.id}] Pruned {pruned} unresolved alterx candidates")

    logger.info(
        f"[dnsx:{session.id}] Resolved {len(activated)}/{len(subs)} subdomains "
        f"to {len(ip_objs)} public IPs"
    )
    return activated
