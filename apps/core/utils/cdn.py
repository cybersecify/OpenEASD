"""CDN IP range detection — no TLS or port findings on CDN/shared edge IPs.

IPs that belong to shared CDN anycast ranges are not the customer's servers.
Port and TLS probes on them hit CDN edge nodes, not the origin, producing
unreliable results (Cloudflare dropping TLS handshakes → false-positive
unencrypted_service CRITICAL).

Ranges are hardcoded from each provider's published list — no HTTP calls,
no external deps, safe to call in a tight inner loop.

Sources (all public):
  Cloudflare: https://www.cloudflare.com/ips/
  Fastly:     https://api.fastly.com/public-ip-list (static snapshot)
  CloudFront: AWS ip-ranges.json filtered to CLOUDFRONT service
  Akamai:     Akamai's published edge prefixes
"""

import ipaddress
from functools import lru_cache

# ---------------------------------------------------------------------------
# Published CDN CIDR blocks
# ---------------------------------------------------------------------------

_CDN_CIDRS_RAW: list[str] = [
    # ── Cloudflare ──────────────────────────────────────────────────────────
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    # Cloudflare IPv6
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",

    # ── Fastly ───────────────────────────────────────────────────────────────
    "23.235.32.0/20",
    "43.249.72.0/22",
    "103.244.50.0/24",
    "103.245.222.0/23",
    "103.245.224.0/24",
    "104.156.80.0/20",
    "140.248.64.0/18",
    "140.248.128.0/17",
    "151.101.0.0/16",
    "157.52.64.0/18",
    "167.82.0.0/17",
    "167.82.128.0/20",
    "167.82.160.0/20",
    "167.82.224.0/20",
    "172.111.64.0/18",
    "185.31.16.0/22",
    "199.27.72.0/21",
    "199.232.0.0/16",

    # ── AWS CloudFront ───────────────────────────────────────────────────────
    "52.84.0.0/15",
    "54.182.0.0/16",
    "54.192.0.0/16",
    "54.230.0.0/16",
    "54.239.128.0/18",
    "64.252.64.0/18",
    "65.9.128.0/18",
    "70.132.0.0/18",
    "99.84.0.0/16",
    "143.204.0.0/16",
    "204.246.164.0/22",
    "204.246.168.0/22",
    "204.246.174.0/23",
    "204.246.176.0/20",
    "205.251.192.0/19",
    "216.137.32.0/19",

    # ── Akamai edge ──────────────────────────────────────────────────────────
    "23.32.0.0/11",
    "23.64.0.0/14",
    "23.72.0.0/13",
    "72.246.0.0/15",
    "95.100.0.0/15",
    "96.16.0.0/15",
    "96.6.0.0/15",
    "184.24.0.0/13",
    "184.50.0.0/15",
    "184.84.0.0/14",
    "184.86.0.0/15",
]

# ---------------------------------------------------------------------------
# Build lookup structure once, on first call
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _cdn_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    nets = []
    for cidr in _CDN_CIDRS_RAW:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            # Skip a malformed entry in the hardcoded list rather than break
            # every scan — a bad CIDR here is a typo, not runtime input.
            continue
    return tuple(nets)


def is_cdn_ip(ip: str) -> bool:
    """Return True if *ip* belongs to a known CDN/shared-edge anycast range.

    Safe to call for every discovered IP — uses a cached tuple of network
    objects built once from the hardcoded list above.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _cdn_networks())
