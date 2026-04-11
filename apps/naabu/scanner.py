"""Naabu scanner — orchestrator: collect → analyze → save (top 100 TCP)."""

import logging

from apps.core.assets.models import IPAddress, Port
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_naabu(session) -> list:
    """Run naabu against all public IPs discovered for the session."""
    targets = list(
        IPAddress.objects.filter(session=session).values_list("address", flat=True).distinct()
    )
    if not targets:
        logger.info(f"[naabu:{session.id}] No public IPs to scan")
        return []

    records = collect(session, targets)
    objs = analyze(session, records)

    if objs:
        Port.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(Port.objects.filter(session=session, source="naabu"))
    logger.info(f"[naabu:{session.id}] Found {len(saved)} open ports")
    return saved
