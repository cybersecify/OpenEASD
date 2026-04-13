from apps.core.findings.models import Finding
from apps.core.scans.models import ScanSession


def sidebar_counts(request):
    """
    Inject sidebar badge counts into every template context.

    sidebar_finding_badge  — count of open critical+high findings
    sidebar_running_count  — count of currently running scan sessions
    """
    finding_badge = Finding.objects.filter(
        severity__in=["critical", "high"],
        status="open",
    ).count()

    running_count = ScanSession.objects.filter(status="running").count()

    return {
        "sidebar_finding_badge": finding_badge,
        "sidebar_running_count": running_count,
    }
