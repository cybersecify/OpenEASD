"""Amass scanner — thin orchestrator calling collector then analyzer."""

import logging

from apps.core.assets.models import Subdomain
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_amass(session) -> list:
    """Run amass against session.domain, save to shared assets, return Subdomain list."""
    records = collect(session)
    if not records:
        return []

    objs = analyze(session, records)
    if objs:
        Subdomain.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(Subdomain.objects.filter(session=session, source="amass"))
    logger.info(f"[amass:{session.id}] Saved {len(saved)} subdomains")
    return saved
