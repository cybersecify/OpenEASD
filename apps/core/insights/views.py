"""Insights views — reads pre-computed summaries, no live aggregation."""

from django.contrib.auth.decorators import login_required
from django.db.models import F, Max
from django.shortcuts import render

from apps.core.domains.models import Domain
from .models import ScanSummary, FindingTypeSummary


@login_required
def insights(request):
    active_domains = Domain.objects.filter(is_active=True).values_list("name", flat=True)

    summaries = (
        ScanSummary.objects
        .filter(domain__in=active_domains)
        .select_related("session")
        .order_by("scan_date")[:10]
    )

    scan_trend = [
        {
            "label": f"{s.domain} ({s.scan_date.strftime('%b %d %H:%M')})",
            "critical": s.critical_count,
            "high": s.high_count,
            "medium": s.medium_count,
            "low": s.low_count,
        }
        for s in summaries
    ]

    delta_trend = [
        {
            "label": f"{s.domain} ({s.scan_date.strftime('%b %d %H:%M')})",
            "new": s.new_exposures,
            "removed": s.removed_exposures,
        }
        for s in summaries
    ]

    latest_summary_ids = (
        ScanSummary.objects
        .filter(domain__in=active_domains)
        .values("domain")
        .annotate(latest_id=Max("id"))
        .values_list("latest_id", flat=True)
    )
    top_hosts = (
        ScanSummary.objects
        .filter(id__in=latest_summary_ids)
        .annotate(count=F("total_findings"))
        .order_by("-count")
        .values("domain", "count")[:5]
    )

    top_finding_types = FindingTypeSummary.objects.order_by("-occurrence_count")[:8]

    return render(request, "insights.html", {
        "scan_trend": scan_trend,
        "delta_trend": delta_trend,
        "top_hosts": top_hosts,
        "top_finding_types": top_finding_types,
        "expiring_ssl": [],
    })
