from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.shortcuts import render

from apps.core.data.domains.models import Domain
from apps.core.data.findings.models import Finding
from apps.core.engine.scans.models import ScanSession

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_ACTIVE_STATUSES = ("pending", "running")


def _severity_counts(qs):
    """Return [(severity, count)] for a Finding queryset, in severity order, non-zero only."""
    raw = dict(qs.values_list("severity").annotate(n=Count("id")))
    return [(sev, raw.get(sev, 0)) for sev in SEVERITY_ORDER if raw.get(sev, 0)]


@login_required
def dashboard(request):
    domains = list(Domain.objects.all())
    for d in domains:
        d.last_scan = ScanSession.objects.filter(domain=d.name).order_by("-start_time").first()
    open_findings = Finding.objects.filter(status="open")
    ctx = {
        "domains": domains,
        "active_domains": sum(1 for d in domains if d.is_active),
        "total_scans": ScanSession.objects.count(),
        "recent_scans": ScanSession.objects.order_by("-start_time")[:10],
        "running": ScanSession.objects.filter(status__in=_ACTIVE_STATUSES).count(),
        "findings_total": open_findings.count(),
        "findings_by_severity": _severity_counts(open_findings),
        "urgent_findings": open_findings.filter(severity__in=["critical", "high"])
        .select_related("session")
        .order_by("-discovered_at")[:10],
    }
    return render(request, "mvp/dashboard.html", ctx)


@login_required
def dashboard_activity(request):
    """HTMX partial: live scan activity, polled every 5s."""
    ctx = {
        "running": ScanSession.objects.filter(status__in=_ACTIVE_STATUSES).count(),
        "recent_scans": ScanSession.objects.order_by("-start_time")[:10],
    }
    return render(request, "mvp/_activity.html", ctx)
