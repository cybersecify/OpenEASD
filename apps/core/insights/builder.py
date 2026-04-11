"""
Insights builder — called once at scan completion.

To add a new tool: append to TOOL_FINDING_SOURCES.
  ("tool_name", "related_manager_name_on_session", "severity_field_name")

All tool finding models must have a `severity` field with values:
  critical / high / medium / low
"""

import logging

from django.db.models import Count, F, Max
from django.utils import timezone as django_tz

from apps.core.domains.models import Domain
from apps.core.scans.models import ScanDelta, ScanSession
from .models import ScanSummary, FindingTypeSummary

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

logger = logging.getLogger(__name__)

SEVERITIES = ["critical", "high", "medium", "low"]


def build_insights(session) -> None:
    """Compute and store insights for a completed scan session."""
    from apps.core.findings.models import Finding

    logger.info(f"[insights] Building summary for session {session.id}")

    findings_qs = Finding.objects.filter(session=session)

    counts = {sev: 0 for sev in SEVERITIES}
    sev_rows = findings_qs.values("severity").annotate(total=Count("id"))
    for row in sev_rows:
        if row["severity"] in counts:
            counts[row["severity"]] = row["total"]

    tool_breakdown: dict[str, int] = {}
    for row in findings_qs.values("source").annotate(total=Count("id")):
        tool_breakdown[row["source"]] = row["total"]

    # Total includes info-severity findings (important: domain_security BIMI is info)
    total = findings_qs.count()
    new_exp = ScanDelta.objects.filter(session=session, change_type="new").count()
    removed_exp = ScanDelta.objects.filter(session=session, change_type="removed").count()

    ScanSummary.objects.update_or_create(
        session=session,
        defaults={
            "domain": session.domain,
            "scan_date": session.end_time or django_tz.now(),
            "total_findings": total,
            "new_exposures": new_exp,
            "removed_exposures": removed_exp,
            "tool_breakdown": tool_breakdown,
            **{f"{sev}_count": counts[sev] for sev in SEVERITIES},
        },
    )

    _rebuild_finding_type_summaries()
    logger.info(f"[insights] Summary built for session {session.id}: {total} total findings")


def _latest_session_ids_for_domains(domains: list) -> list:
    """Return the latest completed ScanSession id per domain."""
    rows = (
        ScanSession.objects
        .filter(domain__in=domains, status="completed")
        .values("domain")
        .annotate(latest_id=Max("id"))
    )
    return [r["latest_id"] for r in rows]


def _rebuild_finding_type_summaries() -> None:
    """Recompute global finding type aggregates — latest scan per domain only."""
    from apps.core.findings.models import Finding

    active_domains = list(Domain.objects.values_list("name", flat=True))
    latest_ids = _latest_session_ids_for_domains(active_domains)
    aggregated: dict[tuple, dict] = {}

    def _merge(key, severity, count, last_seen):
        existing = aggregated.get(key)
        aggregated[key] = {
            "severity": severity if not existing or
                _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(existing["severity"], 0)
                else existing["severity"],
            "occurrence_count": (existing["occurrence_count"] if existing else 0) + count,
            "last_seen": last_seen if not existing or last_seen > existing["last_seen"]
                else existing["last_seen"],
        }

    try:
        rows = (
            Finding.objects
            .filter(session_id__in=latest_ids)
            .exclude(source="nmap")
            .values("title", "check_type", "severity")
            .annotate(count=Count("id"), last=Max("discovered_at"))
        )
        for row in rows:
            _merge((row["title"], row["check_type"]), row["severity"], row["count"], row["last"])
    except Exception as e:
        logger.warning(f"[insights] Finding aggregation failed: {e}")

    try:
        # Nmap CVEs grouped by CVE id (stored in extra JSON)
        rows = (
            Finding.objects
            .filter(session_id__in=latest_ids, source="nmap")
            .values("extra__cve", "severity")
            .annotate(count=Count("id"), last=Max("discovered_at"))
        )
        for row in rows:
            cve = row.get("extra__cve") or ""
            _merge((cve, "cve"), row["severity"], row["count"], row["last"])
    except Exception as e:
        logger.warning(f"[insights] Nmap CVE aggregation failed: {e}")

    # Bulk upsert
    for (title, check_type), data in aggregated.items():
        FindingTypeSummary.objects.update_or_create(
            title=title,
            check_type=check_type,
            defaults={
                "severity": data["severity"],
                "occurrence_count": data["occurrence_count"],
                "last_seen": data["last_seen"],
            },
        )
