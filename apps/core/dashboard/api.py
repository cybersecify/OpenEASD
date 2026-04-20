"""Dashboard API router."""

from django.db.models import Max

from ninja import Router

from apps.core.api.auth import auth_bearer
from apps.core.scans.models import ScanSession
from apps.core.findings.models import Finding
from apps.core.domains.models import Domain
from apps.core.insights.models import ScanSummary
from apps.core.assets.models import Subdomain, IPAddress, Port
from apps.core.web_assets.models import URL

router = Router(auth=auth_bearer)


@router.get("/")
def api_dashboard(request):
    active_domains = list(Domain.objects.filter(is_active=True))
    domain_names = [d.name for d in active_domains]

    # Latest summary per domain
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

    # Latest session per domain
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

    # Latest completed session per domain (for asset counts)
    latest_completed_ids = list(
        ScanSession.objects
        .filter(domain__in=domain_names, status="completed")
        .values("domain")
        .annotate(latest_id=Max("id"))
        .values_list("latest_id", flat=True)
    )

    current_critical = 0
    current_high = 0
    domain_status = []

    for domain in active_domains:
        summary = summaries.get(domain.name)
        session = sessions.get(domain.name)
        if summary:
            current_critical += summary.critical_count
            current_high += summary.high_count
        domain_status.append({
            "id": domain.id,
            "domain": domain.name,
            "scan_status": session.status if session else "idle",
            "last_scan": session.start_time.isoformat() if session and session.start_time else None,
            "critical": summary.critical_count if summary else 0,
            "high": summary.high_count if summary else 0,
        })

    running_count = ScanSession.objects.filter(status__in=["pending", "running"]).count()

    urgent_findings = list(
        Finding.objects.filter(
            session_id__in=latest_completed_ids,
            severity__in=["critical", "high"],
        ).select_related("session").order_by("-discovered_at")[:8]
    )

    asset_counts = {
        "subdomains": Subdomain.objects.filter(
            session_id__in=latest_completed_ids, is_active=True
        ).count(),
        "ips": IPAddress.objects.filter(session_id__in=latest_completed_ids).count(),
        "ports": Port.objects.filter(session_id__in=latest_completed_ids).count(),
        "urls": URL.objects.filter(session_id__in=latest_completed_ids).count(),
    }

    return {
        "kpi_domains": len(active_domains),
        "kpi_active_scans": running_count,
        "kpi_critical": current_critical,
        "kpi_high": current_high,
        "kpi_subdomains": asset_counts["subdomains"],
        "kpi_ips": asset_counts["ips"],
        "kpi_ports": asset_counts["ports"],
        "kpi_urls": asset_counts["urls"],
        "domain_status": domain_status,
        "urgent_findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "title": f.title,
                "domain": f.session.domain,
                "source": f.source,
            }
            for f in urgent_findings
        ],
    }
