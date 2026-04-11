"""httpx scanner — orchestrator: read Ports → probe → save URLs.

Acts as the web/non-web classifier between naabu and nmap.

Multiple subdomains can resolve to the same IP (especially behind CDNs like
Cloudflare), so for each open port we generate one probe per (subdomain, port)
combination. This way Cloudflare can route the request via SNI/Host headers,
which a raw IP probe cannot achieve.
"""

import logging

from apps.core.assets.models import Port, URL
from .collector import collect
from .analyzer import analyze

logger = logging.getLogger(__name__)


def run_httpx(session) -> list[URL]:
    """Probe every open port for HTTP/HTTPS, save matches as URL records."""
    ports = list(
        Port.objects.filter(session=session, state="open")
        .select_related("ip_address__subdomain")
    )
    if not ports:
        logger.info(f"[httpx:{session.id}] No open ports to probe")
        return []

    # Build host:port targets. For each port, prefer the subdomain hostname
    # (so CDN-fronted services like Cloudflare resolve correctly via SNI/Host).
    # Fall back to the raw IP only when no subdomain link exists.
    targets = []
    seen = set()
    for p in ports:
        sub = p.ip_address.subdomain if p.ip_address else None
        host = sub.subdomain if sub else p.address
        target = f"{host}:{p.port}"
        if target in seen:
            continue
        seen.add(target)
        targets.append(target)

    records = collect(session, targets)
    objs = analyze(session, records)

    if objs:
        URL.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(URL.objects.filter(session=session, source="httpx"))
    logger.info(f"[httpx:{session.id}] Confirmed {len(saved)} web URLs (out of {len(targets)} probes)")
    return saved
