"""Cluster registered lookalikes by shared hosting ASN.

Turns N isolated `lookalike_domain` findings into a campaign signal: when two or
more lookalikes resolve into the same autonomous system, that shared
infrastructure is an indicator of coordinated phishing — worth prioritising as
one takedown rather than N separate ones.

The signal only means something on networks small enough that co-location is a
choice. On hyperscale clouds, CDNs, and registrar-parking networks, millions of
unrelated domains "share hosting" the way strangers share a parking lot — a
cluster of parked lookalikes on AS16509 (Amazon) proves nothing. Those generic
ASNs are skipped unless the cluster contains a weaponized member (a confirmed
phishing page makes the grouping meaningful even on shared infrastructure).
"""

import logging
from collections import defaultdict

from django.conf import settings

from apps.core.data.findings.models import Finding

logger = logging.getLogger(__name__)

# Networks where co-location carries no campaign signal: hyperscale clouds,
# major CDNs, and registrar / domain-parking infrastructure. Curated, and
# overridable via settings.ASN_CLUSTER_GENERIC_ASNS.
_GENERIC_ASNS = frozenset({
    "16509", "14618",   # Amazon (AWS / Global Accelerator — also Afternic parking)
    "13335",            # Cloudflare
    "15169", "396982",  # Google
    "8075",             # Microsoft
    "54113",            # Fastly
    "16625", "20940",   # Akamai
    "26496",            # GoDaddy
    "22612",            # Namecheap (incl. registrar parking)
    "14061",            # DigitalOcean
    "16276",            # OVH
    "24940",            # Hetzner
    "47846",            # Sedo parking
})


def _generic_asns() -> frozenset:
    override = getattr(settings, "ASN_CLUSTER_GENERIC_ASNS", None)
    return frozenset(str(a) for a in override) if override is not None else _GENERIC_ASNS


def cluster(session, lookalikes: list[dict], asn_by_ip: dict) -> list[Finding]:
    """Build one Finding per ASN shared by ≥2 distinct lookalike candidates.

    lookalikes: ``[{"candidate", "ips": [...], "weaponized": bool}]``
    asn_by_ip:  ``{ip: {"asn", "as_name", "prefix"}}``

    A cluster with any weaponized member (login form / brand impersonation, as
    flagged by typosquat) is `high`; otherwise `medium`.
    """
    members: dict[str, set] = defaultdict(set)      # asn -> {candidate}
    weaponized: dict[str, set] = defaultdict(set)    # asn -> {weaponized candidate}
    as_names: dict[str, str] = {}                    # asn -> name
    prefixes: dict[str, set] = defaultdict(set)      # asn -> {bgp prefix}

    for la in lookalikes:
        touched: set[str] = set()
        for ip in la.get("ips", []):
            info = asn_by_ip.get(ip)
            if not info:
                continue
            asn = info["asn"]
            touched.add(asn)
            as_names.setdefault(asn, info.get("as_name", "") or "")
            if info.get("prefix"):
                prefixes[asn].add(info["prefix"])
        for asn in touched:
            members[asn].add(la["candidate"])
            if la.get("weaponized"):
                weaponized[asn].add(la["candidate"])

    findings: list[Finding] = []
    apex = getattr(session, "domain", "") or ""
    generic = _generic_asns()
    for asn, candidates in members.items():
        if len(candidates) < 2:
            continue  # not a cluster — a single lookalike per ASN is unremarkable
        cands = sorted(candidates)
        weap = sorted(weaponized[asn])
        if str(asn) in generic and not weap:
            # Shared hyperscaler/CDN/parking hosting proves nothing by itself.
            logger.info(
                "asn_cluster: skipping AS%s (%s) — generic shared infrastructure, "
                "no weaponized member (%d lookalikes: %s)",
                asn, as_names.get(asn, ""), len(cands), ", ".join(cands),
            )
            continue
        name = as_names.get(asn) or "unknown network"
        severity = "high" if weap else "medium"
        weap_note = (
            f" {len(weap)} of them show active phishing signals "
            f"(login form / brand impersonation)."
            if weap else ""
        )
        findings.append(Finding(
            session=session,
            source="asn_cluster",
            check_type="lookalike_cluster",
            severity=severity,
            title=f"{len(cands)} lookalike domains share hosting (AS{asn} {name})",
            description=(
                f"{len(cands)} registered lookalikes of {apex} resolve into the same "
                f"autonomous system — AS{asn} ({name}). Shared infrastructure across "
                f"multiple lookalikes indicates coordinated phishing infrastructure "
                f"rather than unrelated registrations.{weap_note} "
                f"Domains: {', '.join(cands)}."
            ),
            remediation=(
                "Treat these as one campaign: file takedowns together, report the "
                f"shared network (AS{asn}) to its hosting provider / registrar, and "
                "monitor the ASN for further lookalikes."
            ),
            target=f"AS{asn}",
            extra={
                "asn": asn,
                "as_name": name,
                "prefixes": sorted(prefixes[asn]),
                "candidates": cands,
                "member_count": len(cands),
                "weaponized": weap,
                "weaponized_count": len(weap),
            },
        ))

    return findings
