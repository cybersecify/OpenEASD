"""Insights views — reads pre-computed summaries + on-the-fly asset metrics."""

from collections import defaultdict

from django.contrib.auth.decorators import login_required
from django.db.models import Count, F, Max, Q
from django.shortcuts import render

from apps.core.assets.models import IPAddress, Port, Subdomain
from apps.core.web_assets.models import URL
from apps.core.domains.models import Domain
from apps.core.scans.models import ScanSession
from apps.core.findings.models import Finding
from .models import FindingTypeSummary, ScanSummary


@login_required
def insights(request):
    active_domains = list(
        Domain.objects.filter(is_active=True).values_list("name", flat=True)
    )

    summaries = (
        ScanSummary.objects
        .filter(domain__in=active_domains)
        .select_related("session")
        .order_by("scan_date")[:10]
    )
    summaries = list(summaries)

    # ----- KPI counts -----
    kpi_open_critical = Finding.objects.filter(severity="critical", status="open").count()
    kpi_open_high = Finding.objects.filter(severity="high", status="open").count()
    kpi_new = summaries[-1].new_exposures if summaries else 0
    kpi_fixed = summaries[-1].removed_exposures if summaries else 0

    # ----- Finding trend (existing) -----
    scan_trend = [
        {
            "label": f"{s.domain} ({s.scan_date.strftime('%b %d %H:%M')})",
            "critical": s.critical_count,
            "high": s.high_count,
            "medium": s.medium_count,
            "low": s.low_count,
            "tool_breakdown": s.tool_breakdown or {},
            "total": s.total_findings,
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

    # ----- Asset growth per scan -----
    session_ids = [s.session_id for s in summaries]
    asset_counts_by_session = _asset_counts_per_session(session_ids)
    asset_growth = [
        {
            "label": s.scan_date.strftime("%b %d %H:%M"),
            "subdomains": asset_counts_by_session.get(s.session_id, {}).get("subdomains", 0),
            "active_subdomains": asset_counts_by_session.get(s.session_id, {}).get("active_subdomains", 0),
            "ips": asset_counts_by_session.get(s.session_id, {}).get("ips", 0),
            "ports": asset_counts_by_session.get(s.session_id, {}).get("ports", 0),
            "urls": asset_counts_by_session.get(s.session_id, {}).get("urls", 0),
        }
        for s in summaries
    ]

    # ----- Latest scan stats -----
    latest_summary_ids = list(
        ScanSummary.objects
        .filter(domain__in=active_domains)
        .values("domain")
        .annotate(latest_id=Max("id"))
        .values_list("latest_id", flat=True)
    )
    latest_session_ids = [
        s.session_id for s in ScanSummary.objects.filter(id__in=latest_summary_ids)
    ]

    top_hosts = list(
        ScanSummary.objects
        .filter(id__in=latest_summary_ids)
        .annotate(count=F("total_findings"))
        .order_by("-count")
        .values("domain", "count")[:5]
    )

    top_finding_types = FindingTypeSummary.objects.order_by("-occurrence_count")[:10]

    # ----- CVE severity distribution (latest scans only) -----
    severity_dist = (
        Finding.objects
        .filter(session_id__in=latest_session_ids, source="nmap")
        .values("severity")
        .annotate(count=Count("id"))
    )
    severity_distribution = {row["severity"]: row["count"] for row in severity_dist}

    # ----- Top vulnerable services (group by service+version) -----
    # Fetch raw findings and group in Python — Django's JSONField + SQLite
    # don't support Max() on json-extracted fields reliably.
    nmap_findings = Finding.objects.filter(
        session_id__in=latest_session_ids, source="nmap"
    ).only("extra")

    services_agg: dict[tuple[str, str], dict] = {}
    for f in nmap_findings:
        service = (f.extra or {}).get("service", "") or ""
        version = (f.extra or {}).get("version", "") or ""
        cvss = (f.extra or {}).get("cvss_score") or 0
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            cvss = 0.0
        key = (service, version)
        agg = services_agg.setdefault(key, {"service": service, "version": version, "cve_count": 0, "max_cvss": 0.0})
        agg["cve_count"] += 1
        if cvss > agg["max_cvss"]:
            agg["max_cvss"] = cvss

    top_services = sorted(
        services_agg.values(),
        key=lambda r: r["cve_count"],
        reverse=True,
    )[:5]

    # Chart data passed to template — Django's json_script filter encodes safely
    chart_data = {
        "asset_growth_labels": [r["label"] for r in asset_growth],
        "asset_growth_subdomains": [r["active_subdomains"] for r in asset_growth],
        "asset_growth_ips": [r["ips"] for r in asset_growth],
        "asset_growth_ports": [r["ports"] for r in asset_growth],
        "asset_growth_urls": [r["urls"] for r in asset_growth],
        "severity_distribution": severity_distribution,
    }

    return render(request, "insights.html", {
        "scan_trend": scan_trend,
        "delta_trend": delta_trend,
        "top_hosts": top_hosts,
        "top_finding_types": top_finding_types,
        "asset_growth": asset_growth,
        "top_services": top_services,
        "severity_distribution": severity_distribution,
        "chart_data": chart_data,
        "kpi_open_critical": kpi_open_critical,
        "kpi_open_high": kpi_open_high,
        "kpi_new": kpi_new,
        "kpi_fixed": kpi_fixed,
    })


def _asset_counts_per_session(session_ids: list[int]) -> dict[int, dict]:
    """Return {session_id: {subdomains, active_subdomains, ips, ports, urls}}."""
    if not session_ids:
        return {}

    result: dict[int, dict] = defaultdict(dict)

    sub_rows = (
        Subdomain.objects.filter(session_id__in=session_ids)
        .values("session_id")
        .annotate(total=Count("id"), active=Count("id", filter=Q(is_active=True)))
    )
    for row in sub_rows:
        result[row["session_id"]]["subdomains"] = row["total"]
        result[row["session_id"]]["active_subdomains"] = row["active"]

    for model, key in (
        (IPAddress, "ips"),
        (Port, "ports"),
        (URL, "urls"),
    ):
        rows = (
            model.objects.filter(session_id__in=session_ids)
            .values("session_id")
            .annotate(total=Count("id"))
        )
        for row in rows:
            result[row["session_id"]][key] = row["total"]

    return dict(result)
