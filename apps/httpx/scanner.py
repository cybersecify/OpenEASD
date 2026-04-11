"""httpx scanner — orchestrator: read Ports → probe → save URLs.

Acts as the web/non-web classifier between naabu and nmap.
"""

import logging

from apps.core.assets.models import Port, URL
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_httpx(session) -> list[URL]:
    """Probe every open port for HTTP/HTTPS, save matches as URL records."""
    ports = list(Port.objects.filter(session=session, state="open"))
    if not ports:
        logger.info(f"[httpx:{session.id}] No open ports to probe")
        return []

    # Build host:port targets — httpx tries both http:// and https:// per target
    targets = [f"{p.address}:{p.port}" for p in ports]

    records = collect(session, targets)
    objs = analyze(session, records)

    if objs:
        URL.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(URL.objects.filter(session=session, source="httpx"))
    logger.info(f"[httpx:{session.id}] Confirmed {len(saved)} web URLs (out of {len(targets)} probes)")
    return saved
