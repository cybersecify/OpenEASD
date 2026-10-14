import re

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.core.data.domains.models import Domain, DomainAuthorization
from apps.core.data.findings.models import Finding
from apps.core.engine.scans.models import ScanSession

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_ACTIVE_STATUSES = ("pending", "running")
_VALID_HOSTNAME = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
_MONITORING_INTERVALS = (6, 12, 24, 48, 168)  # same set the /api/ endpoint allows
# Common two-level public suffixes (heuristic; OpenEASD has no public-suffix lib).
_SLD_SUFFIXES = {"co", "com", "net", "org", "gov", "edu", "ac"}


def _clean_domain(raw):
    return (raw or "").strip().lower()


def _apex_label_count(name):
    labels = name.split(".")
    if len(labels) >= 3 and labels[-2] in _SLD_SUFFIXES and len(labels[-1]) == 2:
        return 3
    return 2


def _is_apex(name):
    return len(name.split(".")) == _apex_label_count(name)


def _apex_hint(name):
    n = _apex_label_count(name)
    labels = name.split(".")
    if len(labels) > n:
        apex = ".".join(labels[-n:])
        return (f"{name} is a subdomain; add one apex domain per scan. Add the apex "
                f"'{apex}' instead.")
    return f"{name} is not a registrable apex domain; use an apex like example.com."


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


@login_required
def domains(request):
    rows = list(Domain.objects.select_related("authorization").all())
    for d in rows:
        d.last_scan = ScanSession.objects.filter(domain=d.name).order_by("-start_time").first()
        d.authorized = hasattr(d, "authorization")
    return render(request, "mvp/domains.html", {"domains": rows})


@login_required
@require_POST
def domain_create(request):
    name = _clean_domain(request.POST.get("name"))
    if not _VALID_HOSTNAME.match(name):
        messages.error(request, f"Invalid domain name: {name!r}")
        return redirect("mvp:domains")
    if not _is_apex(name):
        messages.error(request, _apex_hint(name))
        return redirect("mvp:domains")
    _, created = Domain.objects.get_or_create(name=name)
    if created:
        messages.success(request, f"Added {name}.")
    else:
        messages.info(request, f"{name} already exists.")
    return redirect("mvp:domain-detail", name=name)


@login_required
def domain_detail(request, name):
    domain = get_object_or_404(Domain, name=name)
    findings = Finding.objects.filter(session__domain=domain.name, status="open")
    ctx = {
        "domain": domain,
        "authorized": DomainAuthorization.is_authorized(domain.name),
        "authorization": getattr(domain, "authorization", None),
        "scans": ScanSession.objects.filter(domain=domain.name).order_by("-start_time")[:25],
        "open_by_severity": _severity_counts(findings),
        "findings": findings.select_related("session").order_by("-discovered_at")[:100],
        "intervals": _MONITORING_INTERVALS,
    }
    return render(request, "mvp/domain_detail.html", ctx)


@login_required
@require_POST
def domain_authorize(request, name):
    """Self-authorize (single-admin tool): same record the /api/ authorize endpoint
    creates, with an explicit attestation checkbox required."""
    domain = get_object_or_404(Domain, name=name)
    if DomainAuthorization.is_authorized(domain.name):
        messages.info(request, f"{name} is already authorized.")
    elif not request.POST.get("attestation"):
        messages.error(request, "Tick the attestation to confirm you may scan this domain.")
    else:
        auth_type = request.POST.get("auth_type") or "owner"
        if auth_type not in {c[0] for c in DomainAuthorization.AUTH_TYPES}:
            messages.error(request, "Invalid authorization type.")
        else:
            DomainAuthorization.objects.create(
                domain=domain,
                auth_type=auth_type,
                authorized_at=timezone.localdate(),
                authorized_by=request.user.get_username(),
                auth_reference=(request.POST.get("auth_reference") or "").strip()[:500],
            )
            messages.success(request, f"{name} authorized.")
    return redirect("mvp:domain-detail", name=name)


@login_required
@require_POST
def domain_monitoring(request, name):
    domain = get_object_or_404(Domain, name=name)
    raw = (request.POST.get("interval_hours") or "").strip()
    if raw == "":
        domain.monitoring_interval_hours = None
    else:
        try:
            val = int(raw)
        except ValueError:
            val = None
        if val not in _MONITORING_INTERVALS:
            messages.error(request, f"Interval must be one of {list(_MONITORING_INTERVALS)} hours.")
            return redirect("mvp:domain-detail", name=name)
        domain.monitoring_interval_hours = val
    domain.save(update_fields=["monitoring_interval_hours"])
    from apps.core.engine.scheduler.scheduler import sync_domain_monitoring_jobs

    sync_domain_monitoring_jobs()
    messages.success(request, "Monitoring updated.")
    return redirect("mvp:domain-detail", name=name)


@login_required
@require_POST
def domain_delete(request, name):
    domain = get_object_or_404(Domain, name=name)
    if ScanSession.objects.filter(domain=name, status__in=_ACTIVE_STATUSES).exists():
        messages.error(request, f"A scan is active for {name}; stop it before deleting.")
        return redirect("mvp:domain-detail", name=name)
    if _clean_domain(request.POST.get("confirm")) != name.lower():
        messages.error(request, "Type the domain name exactly to confirm deletion.")
        return redirect("mvp:domain-detail", name=name)
    from apps.core.console.insights.models import ScanSummary
    from apps.core.engine.scans.models import ScheduledScan

    with transaction.atomic():
        ScanSession.objects.filter(domain=name).delete()
        ScanSummary.objects.filter(domain=name).delete()
        ScheduledScan.objects.filter(domain=name).delete()
        domain.delete()

    # Match the old /api/ delete: rebuild the finding-type aggregates (so counts
    # don't include the deleted domain) and re-sync monitoring jobs.
    from apps.core.console.insights.builder import rebuild_finding_type_summaries
    from apps.core.engine.scheduler.scheduler import sync_domain_monitoring_jobs

    rebuild_finding_type_summaries()
    sync_domain_monitoring_jobs()
    messages.success(request, f"Deleted {name} and all its data.")
    return redirect("mvp:domains")
