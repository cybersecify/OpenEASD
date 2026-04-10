"""SSL checker scanner — thin orchestrator calling collector then analyzer."""

import logging

from .models import SSLFinding
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_ssl_check(session) -> list:
    """Run SSL/TLS certificate validation, save findings."""
    result = collect(session)

    objs = analyze(session, result)

    if objs:
        SSLFinding.objects.bulk_create(objs)

    logger.info(f"[ssl_checker:{session.id}] Found {len(objs)} SSL findings")
    return objs
