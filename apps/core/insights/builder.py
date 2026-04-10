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

# Registry: (tool_name, related_manager on ScanSession, severity field)
# Add new tools here as they are enabled.
TOOL_FINDING_SOURCES = [
    ("domain_security", "domain_findings", "severity"),
    # ("nuclei",         "nuclei_findings",  "severity"),
    # ("subfinder",      "subdomains",        None),   # no severity field
]


def build_insights(session) -> None:
    """Compute and store insights for a completed scan session."""
    logger.info(f"[insights] Building summary for session {session.id}")

    counts = {sev: 0 for sev in SEVERITIES}
    tool_breakdown = {}

    for tool_name, related_name, sev_field in TOOL_FINDING_SOURCES:
        qs = getattr(session, related_name, None)
        if qs is None:
            continue
        try:
            tool_total = qs.count()
            tool_breakdown[tool_name] = tool_total
            if sev_field:
                for sev in SEVERITIES:
                    counts[sev] += qs.filter(**{sev_field: sev}).count()
        except Exception as e:
            logger.warning(f"[insights] Failed to count {tool_name}: {e}")

    total = sum(counts.values())
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
    active_domains = list(Domain.objects.values_list("name", flat=True))
    latest_ids = _latest_session_ids_for_domains(active_domains)
    aggregated: dict[tuple, dict] = {}

    try:
        from apps.domain_security.models import DomainFinding
        rows = (
            DomainFinding.objects
            .filter(session_id__in=latest_ids)
            .values("title", "check_type", "severity")
            .annotate(count=Count("id"), last=Max("discovered_at"))
        )
        for row in rows:
            key = (row["title"], row["check_type"])
            existing = aggregated.get(key)
            aggregated[key] = {
                # Keep the highest severity seen across all occurrences
                "severity": row["severity"] if not existing or
                    _SEVERITY_RANK.get(row["severity"], 0) > _SEVERITY_RANK.get(existing["severity"], 0)
                    else existing["severity"],
                "occurrence_count": (existing["occurrence_count"] if existing else 0) + row["count"],
                "last_seen": row["last"] if not existing or row["last"] > existing["last_seen"]
                    else existing["last_seen"],
            }
    except Exception as e:
        logger.warning(f"[insights] DomainFinding aggregation failed: {e}")

    # Future tools: add their aggregation here following the same pattern

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
