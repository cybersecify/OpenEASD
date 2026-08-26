"""amass intel execution — passive ASN / IP-range (CIDR) discovery.

Given the target's registrable domain we derive an organisation name and ask
``amass intel`` which Autonomous System Numbers that organisation is registered
to, then enumerate the CIDR netblocks announced by each ASN::

    amass intel -org <org>      → "<asn>, <handle> - <description>" per line
    amass intel -asn <asn>      → "<cidr>" (one netblock per line)

This is *reconnaissance against public registry / BGP data* (WHOIS, RIR, routing
tables). It does not touch the target's own infrastructure — no packets are sent
to any IP inside the discovered ranges. Actively scanning those CIDRs (port
scans, service probes) would widen active scope to hosts that may not be covered
by the scan's DomainAuthorization; that expansion is a deliberate, separate
authorization decision and is intentionally NOT done here (see analyzer.py and
scanner.py). The scan-entry DomainAuthorization gate (apps/core/scans/api.py +
apps/core/scheduler/scheduler.py) already governs whether this tool runs at all,
mirroring how naabu/nmap rely on that same gate rather than re-checking per tool.
"""

import ipaddress
import logging
import re
import subprocess

from django.conf import settings

from apps.core.workflows.exceptions import ToolBinaryMissing, ToolTimeout

logger = logging.getLogger(__name__)

_TIMEOUT = 300

# "714, APPLE-ENGINEERING - Apple Inc."  →  asn=714, description="APPLE-ENGINEERING - Apple Inc."
_ASN_LINE = re.compile(r"^\s*(\d{1,10})\s*,\s*(.+?)\s*$")
# Bare "AS714" / "ASN714" style lines (some amass versions/forks emit these).
_ASN_BARE = re.compile(r"^\s*AS[N]?\s*(\d{1,10})\b\s*(.*?)\s*$", re.IGNORECASE)


def _derive_org(domain: str) -> str:
    """Best-effort organisation label from a registrable domain.

    ``example.com`` → ``example``. This is a heuristic: the second-level label is
    usually the org name amass indexes ASNs under. Not perfect for every TLD, but
    good enough as a seed and cheap to run.
    """
    label = (domain or "").strip().lower().split(".")[0]
    return label


def _run_intel(session, args: list[str]) -> list[str]:
    """Run ``amass intel <args>`` and return non-empty stdout lines.

    Raises ToolBinaryMissing / ToolTimeout so the workflow runner can mark the
    step failed honestly (matching subfinder/alterx), rather than silently
    returning [] on a broken run.
    """
    binary = getattr(settings, "TOOL_AMASS", "amass")
    cmd = [binary, "intel", *args]
    logger.info("[asn_discovery:%s] Running: %s", session.id, " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        logger.error("[asn_discovery:%s] Binary not found: %s", session.id, binary)
        raise ToolBinaryMissing(f"amass binary not found: {binary}")
    except subprocess.TimeoutExpired:
        logger.error("[asn_discovery:%s] amass intel timed out", session.id)
        raise ToolTimeout(f"amass intel timed out after {_TIMEOUT}s")

    if result.returncode != 0:
        logger.warning(
            "[asn_discovery:%s] amass intel exited %s: %s",
            session.id, result.returncode, (result.stderr or "")[:300],
        )

    return [line for line in result.stdout.splitlines() if line.strip()]


def _parse_asns(lines: list[str]) -> list[dict]:
    """Parse ``amass intel -org`` output into [{asn, description}] records."""
    records = []
    seen = set()
    for line in lines:
        match = _ASN_LINE.match(line) or _ASN_BARE.match(line)
        if not match:
            continue
        try:
            asn = int(match.group(1))
        except (ValueError, IndexError):
            continue
        if asn in seen:
            continue
        seen.add(asn)
        description = (match.group(2) or "").strip()
        records.append({"asn": asn, "description": description})
    return records


def _parse_cidrs(lines: list[str]) -> list[str]:
    """Extract valid CIDR netblocks from ``amass intel -asn`` output.

    Defensive: amass versions have emitted either a bare CIDR per line or
    comma/space-separated columns. We validate every token with ipaddress and
    keep only real IPv4/IPv6 networks, deduplicated in first-seen order.
    """
    cidrs = []
    seen = set()
    for line in lines:
        for token in re.split(r"[,\s]+", line.strip()):
            if "/" not in token:
                continue
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError:
                continue
            text = str(network)
            if text not in seen:
                seen.add(text)
                cidrs.append(text)
    return cidrs


def collect(session) -> list[dict]:
    """Discover ASNs + CIDRs owned by the org behind ``session.domain``.

    Returns [{"asn": int, "description": str, "cidrs": [str, ...]}]. Empty list
    when the org resolves to no ASNs.
    """
    org = _derive_org(session.domain)
    if not org:
        logger.info("[asn_discovery:%s] No org label from %r", session.id, session.domain)
        return []

    asn_records = _parse_asns(_run_intel(session, ["-org", org]))
    if not asn_records:
        logger.info("[asn_discovery:%s] No ASNs for org=%r", session.id, org)
        return []

    for record in asn_records:
        record["cidrs"] = _parse_cidrs(
            _run_intel(session, ["-asn", str(record["asn"])])
        )

    logger.info(
        "[asn_discovery:%s] org=%r → %d ASN(s)",
        session.id, org, len(asn_records),
    )
    return asn_records
