"""dnsx result analysis — filters public IPs, builds IPAddress + activates Subdomain."""

import ipaddress
import logging

from apps.core.assets.models import IPAddress

logger = logging.getLogger(__name__)


# RFC 6598 Shared Address Space (CGNAT) — not globally routable.
# Python 3.11's is_private does not cover this range; 3.12+ does.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _is_public(ip_str: str) -> bool:
    """Return True if IP is publicly routable (not private/loopback/link-local/reserved/CGNAT)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip in _CGNAT
    )


def analyze(session, records: list[dict], subdomain_index: dict) -> tuple[list[IPAddress], list]:
    """
    Build IPAddress instances from raw dnsx records.

    Returns (ip_objects_to_create, subdomains_to_activate)
    where subdomains_to_activate is a list of Subdomain instances whose
    is_active should be set to True (caller is responsible for saving them).

    subdomain_index is a dict mapping host name → Subdomain instance.
    """
    ip_objs = []
    activated = []
    seen_pairs = set()  # (subdomain_id, address)

    for record in records:
        host = record["host"]
        sub = subdomain_index.get(host)
        if sub is None:
            continue

        all_ips = list(record.get("a", [])) + list(record.get("aaaa", []))
        public_ips = [ip for ip in all_ips if _is_public(ip)]

        if not public_ips:
            # Resolved but private/internal — do not mark active
            continue

        # Activate subdomain
        if not sub.is_active:
            activated.append(sub)

        # Build unique IPAddress records
        for ip_str in public_ips:
            key = (sub.id, ip_str)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            ip_objs.append(IPAddress(
                session=session,
                subdomain=sub,
                address=ip_str,
                version=ipaddress.ip_address(ip_str).version,
                source="dnsx",
            ))

    return ip_objs, activated
