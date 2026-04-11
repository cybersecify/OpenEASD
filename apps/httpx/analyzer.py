"""httpx result analysis — builds URL records linked to Port + Subdomain."""

import logging

from apps.core.assets.models import Port, URL

logger = logging.getLogger(__name__)


def analyze(session, records: list[dict]) -> list[URL]:
    """Build URL asset instances from raw httpx records.

    Links each URL back to:
      - Port (via address + port match)
      - Subdomain (via the IP address resolved by dnsx)
    """
    if not records:
        return []

    # Build a (address, port) → Port FK lookup
    port_map = {
        (p.address, p.port): p
        for p in Port.objects.filter(session=session).select_related("ip_address__subdomain")
    }

    objs = []
    seen = set()  # url string

    for r in records:
        url_str = r.get("url", "").strip()
        if not url_str or url_str in seen:
            continue
        seen.add(url_str)

        host = r.get("host") or r.get("input", "").split(":")[0]
        port_str = r.get("port") or ""
        try:
            port_num = int(port_str) if port_str else None
        except ValueError:
            port_num = None

        port_fk = port_map.get((host, port_num)) if port_num else None
        sub_fk = port_fk.ip_address.subdomain if port_fk and port_fk.ip_address else None

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
