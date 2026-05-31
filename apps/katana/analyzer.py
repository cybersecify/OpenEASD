"""katana result analysis — builds URL records from crawled endpoints."""

import logging
from urllib.parse import urlparse

from apps.core.assets.models import Subdomain
from apps.core.web_assets.models import URL

logger = logging.getLogger(__name__)

_DEFAULT_PORTS = {"http": 80, "https": 443}


def analyze(session, records: list[dict]) -> list[URL]:
    """Build URL asset instances from raw katana JSONL records.

    Port and Subdomain FKs are resolved by matching the crawled URL's
    host and port against existing httpx URL rows for this session —
    httpx has already resolved and linked those assets.
    """
    if not records:
        return []

    # Build (host, port_number) → port_fk from httpx URLs already in session
    httpx_urls = URL.objects.filter(session=session, source="httpx").select_related("port", "subdomain")
    port_map = {}
    sub_map = {}
    for u in httpx_urls:
        if u.host and u.port_number is not None:
            port_map[(u.host, u.port_number)] = u.port
            if u.subdomain:
                sub_map[u.host] = u.subdomain

    # Also build subdomain map from session subdomains for any host not in httpx
    for s in Subdomain.objects.filter(session=session):
        if s.subdomain not in sub_map:
            sub_map[s.subdomain] = s

    objs = []
    seen = set()

    for r in records:
        endpoint = (r.get("request") or {}).get("endpoint", "").strip()
        if not endpoint or endpoint in seen:
            continue
        seen.add(endpoint)

        parsed = urlparse(endpoint)
        scheme = parsed.scheme or ""
        host = parsed.hostname or ""
        if not host:
            continue

        # Explicit port in URL, else default for scheme
        if parsed.port:
            port_num = parsed.port
        else:
            port_num = _DEFAULT_PORTS.get(scheme)

        port_fk = port_map.get((host, port_num)) if port_num else None
        sub_fk = sub_map.get(host)

        objs.append(URL(
            session=session,
            port=port_fk,
            subdomain=sub_fk,
            url=endpoint,
            scheme=scheme,
            host=host,
            port_number=port_num,
            source="katana",
        ))

    return objs
