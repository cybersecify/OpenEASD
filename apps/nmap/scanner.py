"""Nmap scanner — thin orchestrator calling collector then analyzer."""

import logging

from .models import ServiceResult
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_nmap(session, domain: str = None) -> list:
    """Run nmap service detection against domain, save results, return ServiceResult list."""
    if domain is None:
        domain = session.domain

    xml_output = collect(session, domain)

    objs = analyze(session, xml_output, domain)

    if objs:
        ServiceResult.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(session.services.all())
    logger.info(f"[nmap:{session.id}] Found {len(saved)} services")
    return saved
