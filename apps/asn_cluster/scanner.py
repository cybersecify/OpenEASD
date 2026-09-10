"""asn_cluster scanner — orchestrator: read typosquat lookalikes → IP→ASN → cluster.

Reads the `lookalike_domain` findings typosquat already wrote (shared DB data,
not a cross-tool import), resolves their A-record IPs to ASNs via Team Cymru, and
groups lookalikes that share an autonomous system into cluster findings. No-op
(returns []) when there are fewer than two registered, IP-bearing lookalikes to
correlate. Never raises — a lookup failure just drops that IP.
"""

import logging

from apps.core.data.findings.models import Finding
from .collector import lookup_asn
from .analyzer import cluster

logger = logging.getLogger(__name__)

# Safety cap on distinct IPs looked up per scan (each = up to 2 DNS queries).
_MAX_IPS = 256


def run_asn_cluster(session) -> list[Finding]:
    lookalikes: list[dict] = []
    ips: set[str] = set()

    qs = Finding.objects.filter(
        session=session, source="typosquat", check_type="lookalike_domain"
    )
    for f in qs:
        extra = f.extra if isinstance(f.extra, dict) else {}
        cand_ips = extra.get("resolved_ips") or []
        if not cand_ips:
            continue  # only A-record-bearing lookalikes can be clustered by host
        lookalikes.append({
            "candidate": extra.get("candidate") or f.target,
            "ips": cand_ips,
            # typosquat marks weaponized lookalikes (login form / brand) as high.
            "weaponized": f.severity == "high",
        })
        ips.update(cand_ips)

    if len(lookalikes) < 2:
        logger.info(
            "[asn_cluster:%s] %d clusterable lookalike(s) — nothing to correlate",
            session.id, len(lookalikes),
        )
        return []

    asn_by_ip: dict = {}
    for ip in list(ips)[:_MAX_IPS]:
        info = lookup_asn(ip)
        if info:
            asn_by_ip[ip] = info

    findings = cluster(session, lookalikes, asn_by_ip)
    if findings:
        Finding.objects.bulk_create(findings)

    logger.info(
        "[asn_cluster:%s] %d lookalike(s) over %d ASN-resolved IP(s) → %d cluster(s)",
        session.id, len(lookalikes), len(asn_by_ip), len(findings),
    )
    return findings
