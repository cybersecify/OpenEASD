"""Naabu scanner — thin orchestrator calling collector then analyzer."""

import logging

from .models import PortResult
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_naabu(session, targets: list) -> list:
    """Run naabu port scan against targets, save results, return PortResult list."""
    records = collect(session, targets)

    objs = analyze(session, records)

    if objs:
        PortResult.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(session.port_results.all())
    logger.info(f"[naabu:{session.id}] Found {len(saved)} open ports")
    return saved
