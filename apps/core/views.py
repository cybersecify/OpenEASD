"""Core app views."""

from django.shortcuts import render
from django.db import connection
from django.db.utils import OperationalError
from django.contrib.auth.decorators import login_required

from apps.scans.models import ScanSession, ScanDelta
from apps.subfinder.models import Subdomain
from apps.naabu.models import PortResult
from apps.nmap.models import ServiceResult
from apps.nuclei.models import NucleiFinding
from apps.dns_analyzer.models import DNSFinding
from apps.ssl_checker.models import SSLFinding
from apps.email_security.models import EmailFinding


@login_required
def dashboard(request):
    # Scan health
    recent_scans = ScanSession.objects.all()[:5]
    last_completed = ScanSession.objects.filter(status="completed").first()
    running_count = ScanSession.objects.filter(status="running").count()
    total_scans = ScanSession.objects.count()

    # Attack surface totals
    total_subdomains = Subdomain.objects.count()
    total_open_ports = PortResult.objects.count()
    total_services = ServiceResult.objects.count()

    # Severity breakdown across all finding types
    severity_counts = {}
    for sev in ("critical", "high", "medium", "low"):
        severity_counts[sev] = (
            NucleiFinding.objects.filter(severity=sev).count()
            + DNSFinding.objects.filter(severity=sev).count()
            + SSLFinding.objects.filter(severity=sev).count()
            + EmailFinding.objects.filter(severity=sev).count()
        )

    # New exposures from delta (change_type=new)
    new_exposures = ScanDelta.objects.filter(change_type="new").select_related("session")[:6]

    # Recent critical/high nuclei findings
    urgent_findings = NucleiFinding.objects.filter(
        severity__in=["critical", "high"]
    ).select_related("session").order_by("-discovered_at")[:5]

    return render(request, "dashboard.html", {
        "recent_scans": recent_scans,
        "last_completed": last_completed,
        "running_count": running_count,
        "total_scans": total_scans,
        "total_subdomains": total_subdomains,
        "total_open_ports": total_open_ports,
        "total_services": total_services,
        "severity_counts": severity_counts,
        "new_exposures": new_exposures,
        "urgent_findings": urgent_findings,
    })


@login_required
def insights(request):
    # Finding trend: last 10 completed scans with severity counts
    completed_scans = ScanSession.objects.filter(status="completed").order_by("-start_time")[:10]

    scan_trend = []
    for scan in reversed(list(completed_scans)):
        scan_trend.append({
            "label": f"{scan.domain} ({scan.start_time.strftime('%b %d %H:%M')})",
            "critical": NucleiFinding.objects.filter(session=scan, severity="critical").count()
                        + DNSFinding.objects.filter(session=scan, severity="critical").count()
                        + SSLFinding.objects.filter(session=scan, severity="critical").count()
                        + EmailFinding.objects.filter(session=scan, severity="critical").count(),
            "high": NucleiFinding.objects.filter(session=scan, severity="high").count()
                    + DNSFinding.objects.filter(session=scan, severity="high").count()
                    + SSLFinding.objects.filter(session=scan, severity="high").count()
                    + EmailFinding.objects.filter(session=scan, severity="high").count(),
        })

    # Delta summary: new vs removed per scan
    delta_trend = []
    for scan in reversed(list(completed_scans)):
        delta_trend.append({
            "label": f"{scan.domain} ({scan.start_time.strftime('%b %d %H:%M')})",
            "new": ScanDelta.objects.filter(session=scan, change_type="new").count(),
            "removed": ScanDelta.objects.filter(session=scan, change_type="removed").count(),
        })

    # Top vulnerable hosts (most findings)
    from django.db.models import Count
    top_hosts = (
        NucleiFinding.objects
        .values("host")
        .annotate(count=Count("id"))
        .order_by("-count")[:5]
    )

    # Most common finding types
    top_finding_types = (
        NucleiFinding.objects
        .values("template_name", "severity")
        .annotate(count=Count("id"))
        .order_by("-count")[:8]
    )

    # SSL certificates expiring soon
    from django.utils import timezone
    import datetime
    soon = timezone.now() + datetime.timedelta(days=30)
    expiring_ssl = SSLFinding.objects.filter(
        expiry_date__isnull=False,
        expiry_date__lte=soon,
    ).order_by("expiry_date")[:5]

    return render(request, "insights.html", {
        "scan_trend": scan_trend,
        "delta_trend": delta_trend,
        "top_hosts": top_hosts,
        "top_finding_types": top_finding_types,
        "expiring_ssl": expiring_ssl,
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
