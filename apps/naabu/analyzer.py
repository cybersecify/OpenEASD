"""Naabu result analysis — model building layer."""

import logging

from .models import PortResult

logger = logging.getLogger(__name__)


def analyze(session, records: list[dict]) -> list:
    """Build PortResult model instances from raw collector records."""
    objs = []
    for record in records:
        objs.append(PortResult(
            session=session,
            host=record["host"],
            port=record["port"],
            protocol=record["protocol"],
        ))
    return objs
