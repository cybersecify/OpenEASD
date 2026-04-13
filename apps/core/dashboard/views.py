"""Core app views."""

from django.db import connection
from django.db.models import Max
from django.db.utils import OperationalError
from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from apps.core.scans.models import ScanSession
from apps.core.findings.models import Finding
from apps.core.domains.models import Domain
from apps.core.insights.models import ScanSummary
from apps.core.assets.models import Subdomain, IPAddress, Port
from apps.core.web_assets.models import URL


@login_required
def dashboard(request):
    active_domains = list(Domain.objects.filter(is_active=True))
    domain_names = [d.name for d in active_domains]

    # Latest summary per domain — resolved by ID to avoid scan_date collisions
    latest_summary_ids = list(
        ScanSummary.objects
        .filter(domain__in=domain_names)
        .values("domain")
        .annotate(latest_id=Max("id"))
        .values_list("latest_id", flat=True)
    )
    summaries = {
        s.domain: s
        for s in ScanSummary.objects.filter(id__in=latest_summary_ids)
    }

    # Latest session per domain — resolved by ID to avoid start_time collisions
    latest_session_ids = list(
        ScanSession.objects
        .filter(domain__in=domain_names)
        .values("domain")
        .annotate(latest_id=Max("id"))
        .values_list("latest_id", flat=True)
    )
    sessions = {
        s.domain: s
        for s in ScanSession.objects.filter(id__in=latest_session_ids)
    }

    # Latest completed session per domain (for asset counts — independent of latest session)
    latest_completed_ids = list(
        ScanSession.objects
        .filter(domain__in=domain_names, status="completed")
        .values("domain")
        .annotate(latest_id=Max("id"))
        .values_list("latest_id", flat=True)
    )

    domain_status = []
    current_critical = 0
    current_high = 0

    for domain in active_domains:
        summary = summaries.get(domain.name)
        session = sessions.get(domain.name)
        domain_status.append({
            "domain": domain,
            "summary": summary,
            "latest_session": session,
        })
        if summary:
            current_critical += summary.critical_count
            current_high += summary.high_count

    running_count = ScanSession.objects.filter(status__in=["pending", "running"]).count()

    urgent_findings = list(
        Finding.objects.filter(
            session_id__in=latest_completed_ids,
            severity__in=["critical", "high"],
        ).select_related("session").order_by("-discovered_at")[:8]
    )

    # Asset counts across latest completed scans (the current attack surface).
    # 4 queries (one per model) is the ORM minimum — they query different tables.
    asset_counts = {
        "subdomains": Subdomain.objects.filter(
            session_id__in=latest_completed_ids, is_active=True
        ).count(),
        "ips": IPAddress.objects.filter(session_id__in=latest_completed_ids).count(),
        "ports": Port.objects.filter(session_id__in=latest_completed_ids).count(),
        "urls": URL.objects.filter(session_id__in=latest_completed_ids).count(),
    }

    # Get the single latest completed session for asset card links
    latest_completed_session = (
        ScanSession.objects.filter(id__in=latest_completed_ids).order_by("-id").first()
    )

    return render(request, "dashboard.html", {
        "domain_status": domain_status,
        "current_critical": current_critical,
        "current_high": current_high,
        "running_count": running_count,
        "active_domain_count": len(active_domains),
        "urgent_findings": urgent_findings,
        "asset_counts": asset_counts,
        "latest_scan_uuid": latest_completed_session.uuid if latest_completed_session else None,
    })


@login_required
def health_check(request):
    try:
        connection.ensure_connection()
        db_status = "connected"
    except OperationalError:
        db_status = "disconnected"

    return render(request, "health.html", {
        "db_status": db_status,
        "service": "OpenEASD",
        "version": "1.0.0",
    })
