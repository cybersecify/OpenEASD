"""CDN edge-IP detection for Shodan exposure findings.

A domain fronted by a CDN (Cloudflare, Fastly, …) resolves to the CDN's shared
edge IPs, not the customer's own servers. Shodan reports ports 80/443 open on
those edge IPs — which is true for *every* site on that CDN and is not the
target's asset, so a "publicly exposed services" finding on a CDN edge is pure
noise. We skip exposure findings for these ranges.

This never hides a real origin exposure: a leaked origin server is on the
customer's own IP (not a CDN range), so it still gets flagged. CVE findings are
kept regardless of CDN membership (rare and high-signal).

Ranges are the well-known, stable published CDN blocks. Cloudflare's are from
cloudflare.com/ips; a few other common SaaS CDNs are included. Unknown/unparsable
IPs are treated as non-CDN (fail-safe toward reporting).
"""

import ipaddress
import logging

logger = logging.getLogger(__name__)

# name -> list of CIDR strings (IPv4 + IPv6)
_CDN_RANGES: dict[str, list[str]] = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    ],
    "Fastly": ["151.101.0.0/16", "2a04:4e40::/32"],
    "CloudFront": ["2600:9000::/28"],
}

# Pre-parse to network objects once at import.
_CDN_NETS: list[tuple[str, "ipaddress._BaseNetwork"]] = []
for _name, _cidrs in _CDN_RANGES.items():
    for _cidr in _cidrs:
        try:
            _CDN_NETS.append((_name, ipaddress.ip_network(_cidr)))
        except ValueError:  # pragma: no cover - static, well-formed list
            logger.warning("shodan.cdn: bad CIDR %s", _cidr)


def is_cdn_ip(ip: str) -> str | None:
    """Return the CDN name if `ip` is in a known CDN edge range, else None.

    Unparsable input returns None (treated as non-CDN — fail toward reporting).
    """
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    for name, net in _CDN_NETS:
        if addr.version == net.version and addr in net:
            return name
    return None
