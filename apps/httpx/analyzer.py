"""httpx result analysis — builds URL records linked to Port + Subdomain."""

import logging

from apps.core.assets.models import Port, Subdomain
from apps.core.web_assets.models import URL

logger = logging.getLogger(__name__)


def analyze(session, records: list[dict]) -> list[URL]:
    """Build URL asset instances from raw httpx records.

    httpx output fields used:
      - url       : "https://www.example.com:443"
      - host      : "www.example.com"  (hostname from input)
      - host_ip   : "104.21.38.252"    (resolved A record)
      - port      : "443"
      - scheme, status_code, title, webserver, content_length

    Links each URL back to:
      - Port (matched by IP + port number)
      - Subdomain (matched by hostname)
    """
    if not records:
        return []

    # (address, port) → Port FK — Port.address is the resolved IP
    port_map = {
        (p.address, p.port): p
        for p in Port.objects.filter(session=session)
    }

    # subdomain string → Subdomain FK
    sub_map = {
        s.subdomain: s
        for s in Subdomain.objects.filter(session=session)
    }

    objs = []
    seen = set()  # url string

    for r in records:
        url_str = r.get("url", "").strip()
        if not url_str or url_str in seen:
            continue
        seen.add(url_str)

        host = r.get("host") or r.get("input", "").split(":")[0]
        host_ip = r.get("host_ip") or ""
        port_str = r.get("port") or ""
        try:
            port_num = int(port_str) if port_str else None
        except ValueError:
            port_num = None

        # Port lookup uses the resolved IP (host_ip), not the hostname
        port_fk = port_map.get((host_ip, port_num)) if (host_ip and port_num) else None

        # Subdomain lookup uses the hostname directly
        sub_fk = sub_map.get(host)

        objs.append(URL(
            session=session,
            port=port_fk,
            subdomain=sub_fk,
            url=url_str,
            scheme=r.get("scheme", ""),
            host=host or "",
            port_number=port_num,
            status_code=r.get("status_code"),
            title=(r.get("title") or "")[:500],
            web_server=(r.get("webserver") or "")[:200],
            content_length=r.get("content_length"),
            source="httpx",
        ))

    return objs
