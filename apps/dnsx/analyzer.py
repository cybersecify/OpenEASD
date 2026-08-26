"""dnsx result analysis — filters public IPs, builds IPAddress + activates Subdomain."""

import ipaddress
import logging

from apps.core.assets.models import IPAddress

logger = logging.getLogger(__name__)


# RFC 6598 Shared Address Space (CGNAT) — not globally routable.
# Python 3.11's is_private does not cover this range; 3.12+ does.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")

# Known CDN edge IP ranges — IPs here belong to CDN infrastructure, not the
# customer's origin servers. Port-scanning or TLS-probing them produces findings
# against the CDN (false positives) rather than the target.
# Sources: cloudflare.com/ips-v4, api.fastly.com/public-ip-list,
#          ip-ranges.amazonaws.com/ip-ranges.json (service=CLOUDFRONT).
_CDN_RANGES = [
    # Cloudflare
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15",
    "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Fastly
    "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
    "103.245.224.0/24", "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17",
    "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
    "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18",
    "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
    # AWS CloudFront
    "13.32.0.0/15", "13.35.0.0/16", "52.46.0.0/18", "52.84.0.0/15",
    "54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/16",
    "64.252.64.0/18", "64.252.128.0/18", "70.132.0.0/18", "99.84.0.0/16",
    "204.246.164.0/22", "204.246.168.0/22", "204.246.172.0/23", "204.246.174.0/23",
    "204.246.176.0/20", "205.251.192.0/19", "205.251.249.0/24",
    "205.251.250.0/23", "205.251.252.0/23", "216.137.32.0/19",
]
_CDN_NETWORKS = [ipaddress.ip_network(r) for r in _CDN_RANGES]


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


def _is_cdn_ip(ip_str: str) -> bool:
    """Return True if the IP belongs to a known CDN edge network."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in _CDN_NETWORKS)


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

        # Activate subdomain — it's publicly reachable even if behind a CDN
        if not sub.is_active:
            activated.append(sub)

        # Only create IPAddress records for non-CDN IPs. CDN edge IPs (Cloudflare,
        # Fastly, CloudFront) are shared infrastructure — port-scanning them
        # produces findings against the CDN, not the customer's origin server.
        scannable_ips = [ip for ip in public_ips if not _is_cdn_ip(ip)]
        for ip_str in scannable_ips:
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
