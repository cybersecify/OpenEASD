"""Subfinder scanner — thin orchestrator calling collector then analyzer."""

import logging

from .models import Subdomain
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_subfinder(session) -> list:
    """Run subfinder against session.domain, save results, return Subdomain queryset."""
    records = collect(session)

    objs = analyze(session, records)

    if objs:
        Subdomain.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(session.subdomains.all())
    logger.info(f"[subfinder:{session.id}] Found {len(saved)} subdomains")
    return saved
