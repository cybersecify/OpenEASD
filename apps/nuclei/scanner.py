"""Nuclei scanner — thin orchestrator calling collector then analyzer."""

import logging

from .models import NucleiFinding
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_nuclei(session, targets: list) -> list:
    """Run nuclei vulnerability scan against targets, save results."""
    records = collect(session, targets)

    objs = analyze(session, records)

    if objs:
        NucleiFinding.objects.bulk_create(objs)

    saved = list(session.nuclei_findings.all())
    logger.info(f"[nuclei:{session.id}] Found {len(saved)} vulnerabilities")
    return saved
