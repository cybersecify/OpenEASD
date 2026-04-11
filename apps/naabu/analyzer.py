"""Naabu result analysis — builds shared Port assets."""

import logging

from apps.core.assets.models import Port, IPAddress

logger = logging.getLogger(__name__)


def analyze(session, records: list[dict]) -> list[Port]:
    """Build shared Port asset instances from raw collector records.

    Looks up the IPAddress for each host so we can attribute the port back
    to a specific subdomain.
    """
    if not records:
        return []

    # Build IP → IPAddress instance map for this session
    ip_map = {ip.address: ip for ip in IPAddress.objects.filter(session=session)}

    objs = []
    seen = set()  # (address, port, protocol)
    for record in records:
        host = record["host"]
        port = record["port"]
        protocol = record["protocol"]
        key = (host, port, protocol)
        if key in seen:
            continue
        seen.add(key)

        objs.append(Port(
            session=session,
            ip_address=ip_map.get(host),
            address=host,
            port=port,
            protocol=protocol,
            state="open",
            source="naabu",
        ))
    return objs
