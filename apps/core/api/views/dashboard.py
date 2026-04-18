from django.db.models import Max

from apps.core.api.decorators import api_login_required
from apps.core.api.serializers import api_response, serialize_scan_session_brief, serialize_finding
from apps.core.scans.models import ScanSession
from apps.core.findings.models import Finding
from apps.core.domains.models import Domain
from apps.core.insights.models import ScanSummary
from apps.core.assets.models import Subdomain, IPAddress, Port
from apps.core.web_assets.models import URL


@api_login_required
def api_dashboard(request):
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

    asset_counts = {
        "subdomains": Subdomain.objects.filter(
            session_id__in=latest_completed_ids, is_active=True
        ).count(),
        "ips": IPAddress.objects.filter(session_id__in=latest_completed_ids).count(),
        "ports": Port.objects.filter(session_id__in=latest_completed_ids).count(),
        "urls": URL.objects.filter(session_id__in=latest_completed_ids).count(),
    }

    latest_completed_session = (
        ScanSession.objects.filter(id__in=latest_completed_ids).order_by("-id").first()
    )

    return api_response({
        "domain_status": [
            {
                "domain": {
                    "id": d["domain"].id,
                    "name": d["domain"].name,
                    "is_active": d["domain"].is_active,
                    "is_primary": d["domain"].is_primary,
                },
                "summary": {
                    "critical_count": d["summary"].critical_count,
                    "high_count": d["summary"].high_count,
                    "medium_count": d["summary"].medium_count,
                    "low_count": d["summary"].low_count,
                    "total_findings": d["summary"].total_findings,
                    "new_exposures": d["summary"].new_exposures,
                    "removed_exposures": d["summary"].removed_exposures,
                } if d["summary"] else None,
                "latest_session": serialize_scan_session_brief(d["latest_session"]) if d["latest_session"] else None,
            }
            for d in domain_status
        ],
        "kpi": {
            "critical": current_critical,
            "high": current_high,
            "running_scans": running_count,
            "active_domains": len(active_domains),
        },
        "urgent_findings": [serialize_finding(f) for f in urgent_findings],
        "asset_counts": asset_counts,
        "latest_scan_uuid": str(latest_completed_session.uuid) if latest_completed_session else None,
    })
