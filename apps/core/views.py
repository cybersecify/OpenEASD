"""Core app views."""

from django.shortcuts import render
from django.db import connection
from django.db.utils import OperationalError
from django.contrib.auth.decorators import login_required

from apps.scans.models import ScanSession
from apps.domain_security.models import DomainFinding
from apps.domains.models import Domain
from apps.insights.models import ScanSummary


@login_required
def dashboard(request):
    active_domains = Domain.objects.filter(is_active=True)

    # Per-domain: latest summary + latest session
    domain_status = []
    current_critical = 0
    current_high = 0
    latest_session_ids = []

    for domain in active_domains:
        latest_summary = (
            ScanSummary.objects.filter(domain=domain.name).order_by("-scan_date").first()
        )
        latest_session = (
            ScanSession.objects.filter(domain=domain.name).order_by("-start_time").first()
        )
        domain_status.append({
            "domain": domain,
            "summary": latest_summary,
            "latest_session": latest_session,
        })
        if latest_summary:
            current_critical += latest_summary.critical_count
            current_high += latest_summary.high_count
        if latest_session and latest_session.status == "completed":
            latest_session_ids.append(latest_session.id)

    running_count = ScanSession.objects.filter(status="running").count()

    # Urgent findings from the latest completed scan per domain only
    urgent_findings = DomainFinding.objects.filter(
        session_id__in=latest_session_ids,
        severity__in=["critical", "high"],
    ).select_related("session").order_by("-discovered_at")[:8]

    return render(request, "dashboard.html", {
        "domain_status": domain_status,
        "current_critical": current_critical,
        "current_high": current_high,
        "running_count": running_count,
        "active_domain_count": active_domains.count(),
        "urgent_findings": urgent_findings,
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
