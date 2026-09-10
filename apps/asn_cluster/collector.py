"""IP → ASN lookup via Team Cymru's keyless DNS service.

Passive: queries Team Cymru (a third party), never the target or the lookalike
domains. Fail-graceful — any DNS failure yields None, never raises.

Team Cymru protocol (IPv4):
  - origin: TXT `<d.c.b.a>.origin.asn.cymru.com`
      → "ASN | BGP Prefix | CC | Registry | Allocated"  (ASN may be a space-list)
  - name:   TXT `AS<n>.asn.cymru.com`
      → "ASN | CC | Registry | Allocated | AS-NAME, CC"
"""

import logging

import dns.resolver
from django.conf import settings

logger = logging.getLogger(__name__)

_DNS_TIMEOUT = getattr(settings, "SCANNER_DNS_TIMEOUT", 5)


def _txt(name: str) -> list[str]:
    """Resolve a TXT record; [] on any failure. Never raises."""
    try:
        r = dns.resolver.Resolver()
        r.timeout = _DNS_TIMEOUT
        r.lifetime = _DNS_TIMEOUT
        answers = r.resolve(name, "TXT")
    except Exception:  # noqa: BLE001 — any resolver failure = "no data"
        return []
    return [b"".join(rd.strings).decode("utf-8", errors="ignore") for rd in answers]


def lookup_asn(ip: str) -> "dict | None":
    """Return ``{"asn", "as_name", "prefix"}`` for an IPv4 address, or None.

    IPv4 only — Team Cymru's ``origin6`` zone would be needed for IPv6; lookalike
    A-records are effectively always v4, so v6 is skipped rather than mis-parsed.
    """
    parts = (ip or "").strip().split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return None

    origin = _txt(f"{'.'.join(reversed(parts))}.origin.asn.cymru.com")
    if not origin:
        return None
    fields = [f.strip() for f in origin[0].split("|")]
    asn = fields[0].split()[0] if fields and fields[0] else ""
    if not asn:
        return None
    prefix = fields[1] if len(fields) > 1 else ""

    as_name = ""
    name_txt = _txt(f"AS{asn}.asn.cymru.com")
    if name_txt:
        nf = [f.strip() for f in name_txt[0].split("|")]
        as_name = nf[-1] if nf else ""

    return {"asn": asn, "as_name": as_name, "prefix": prefix}
