import logging
import re

from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.db import transaction
from django.core.paginator import Paginator
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.core.data.domains.models import Domain, DomainAuthorization
from apps.core.data.findings.models import Finding
from apps.core.engine.scans.models import ScanSession
from apps.core.engine.scans.pipeline import create_scan_session
from apps.core.engine.scans.tasks import run_scan_task
from apps.core.engine.workflows.models import Workflow
from apps.core.engine.workflows.registry import is_passive_tool_set

logger = logging.getLogger(__name__)

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


SCAN_MODE_DEFS = [
    ("Passive Scan Light", "Apex-only passive first look"),
    ("Passive Scan Deep", "Full passive recon (no authorization needed)"),
    ("Active Light", "Fast authorized scan"),
    ("Full Scan", "Complete active scan"),
]


def _workflow_is_passive(workflow):
    """Same signal as scans/api.py::_is_passive_only_scan (immediate scan, workflow tools).
    Workflow has no is_passive attribute; an empty tool set is treated as active (stricter)."""
    tools = workflow.enabled_tools()
    return bool(tools) and is_passive_tool_set(tools)


def _scan_modes():
    out = []
    for name, blurb in SCAN_MODE_DEFS:
        wf = Workflow.objects.filter(name=name).first()
        if wf:
            out.append({"name": name, "blurb": blurb, "workflow_id": wf.id,
                        "needs_auth": not _workflow_is_passive(wf)})
    return out


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
        "scan_modes": _scan_modes(),
        "all_workflows": Workflow.objects.order_by("name"),
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


@login_required
@require_POST
def scan_start(request):
    name = _clean_domain(request.POST.get("domain"))
    domain = get_object_or_404(Domain, name=name)
    back = redirect("mvp:domain-detail", name=domain.name)
    try:
        workflow = Workflow.objects.get(pk=int(request.POST.get("workflow_id", "")))
    except (ValueError, Workflow.DoesNotExist):
        messages.error(request, "Choose a valid scan mode.")
        return back
    if not _is_apex(domain.name):
        messages.error(request, _apex_hint(domain.name))
        return back
    # Authorization gate (mirrors scans/api.py): passive-only workflow bypasses it.
    if not _workflow_is_passive(workflow) and not DomainAuthorization.is_authorized(domain.name):
        messages.error(request, f"{domain.name} must be authorized before an active scan.")
        return back
    session = create_scan_session(domain.name, triggered_by="manual", workflow=workflow)
    if session is None:
        messages.warning(request, "A scan is already running for this domain.")
        return back
    run_scan_task(session.id)
    messages.success(request, f"{workflow.name} scan started for {domain.name}.")
    return redirect("mvp:scan-detail", session_uuid=session.uuid)


def _scan_steps(session):
    """Ordered per-tool step results for this scan's workflow run."""
    from apps.core.engine.workflows.models import WorkflowRun

    run = WorkflowRun.objects.filter(session=session).order_by("-id").first()
    if run is None:
        return []
    return list(run.step_results.order_by("order", "id"))


def _scan_progress_ctx(session):
    steps = _scan_steps(session)
    done = sum(1 for s in steps if s.status in ("completed", "failed", "skipped"))
    all_findings = Finding.objects.filter(session=session)
    return {
        "session": session,
        "active": session.status in _ACTIVE_STATUSES,
        "steps": steps,
        "steps_done": done,
        "steps_total": len(steps),
        "failed_tools": [s.tool for s in steps if s.status == "failed"],
        "skipped_tools": [s.tool for s in steps if s.status == "skipped"],
        "finding_count": all_findings.count(),
        "by_severity": _severity_counts(all_findings),
    }


@login_required
def scan_detail(request, session_uuid):
    session = get_object_or_404(ScanSession, uuid=str(session_uuid))
    ctx = _scan_progress_ctx(session)
    findings = Finding.objects.filter(session=session)
    sev = request.GET.get("sev")
    if sev in SEVERITY_ORDER:
        findings = findings.filter(severity=sev)
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings = sorted(findings, key=lambda f: (rank.get(f.severity, 9), f.source, f.title))
    ctx.update({
        "findings": findings[:500],
        "findings_shown": min(len(findings), 500),
        "findings_total_filtered": len(findings),
        "sev_filter": sev if sev in SEVERITY_ORDER else "",
        "severity_order": SEVERITY_ORDER,
    })
    return render(request, "mvp/scan_detail.html", ctx)


@login_required
def scan_progress(request, session_uuid):
    """HTMX partial polled while the scan runs; on a terminal scan, ask htmx to
    do one full reload (HX-Refresh), which ends polling."""
    from django.http import HttpResponse

    session = get_object_or_404(ScanSession, uuid=str(session_uuid))
    if session.status not in _ACTIVE_STATUSES:
        resp = HttpResponse(status=204)
        resp["HX-Refresh"] = "true"
        return resp
    return render(request, "mvp/_scan_progress.html", _scan_progress_ctx(session))


@login_required
@require_POST
def scan_cancel(request, session_uuid):
    """Stop a scan: same status flip as POST /api/scans/<uuid>/stop/, plus a
    best-effort DBOS workflow cancel."""
    session = get_object_or_404(ScanSession, uuid=str(session_uuid))
    if session.status not in _ACTIVE_STATUSES:
        messages.info(request, "That scan is not running.")
        return redirect("mvp:scan-detail", session_uuid=session_uuid)
    session.status = "cancelled"
    session.end_time = timezone.now()
    session.save(update_fields=["status", "end_time"])
    try:
        from apps.core.engine.scheduler.scheduler import _cancel_workflows_for_sessions

        _cancel_workflows_for_sessions([session.id])
    except Exception:  # noqa: BLE001 - best effort; the status flip stops the pipeline
        logger.warning("[mvp] could not cancel DBOS workflow for scan %s", session.id, exc_info=True)
    messages.success(request, f"Scan cancelled for {session.domain}.")
    return redirect("mvp:scan-detail", session_uuid=session_uuid)


@login_required
def scans(request):
    qs = ScanSession.objects.order_by("-start_time")
    domain = (request.GET.get("domain") or "").strip()
    status = request.GET.get("status") or ""
    if domain:
        qs = qs.filter(domain=domain)
    if status in {c[0] for c in ScanSession.STATUS_CHOICES}:
        qs = qs.filter(status=status)
    else:
        status = ""
    page = Paginator(qs, 50).get_page(request.GET.get("page"))
    return render(request, "mvp/scans.html", {
        "page": page,
        "domain_filter": domain,
        "status_filter": status,
        "status_choices": ScanSession.STATUS_CHOICES,
    })


@login_required
def change_password(request):
    if request.method == "POST":
        form = PasswordChangeForm(request.user, request.POST)
        if len(request.POST.get("new_password1", "")) > 128:
            form.is_bound = True
            form.full_clean()
            form.add_error("new_password1", "Password must be at most 128 characters.")
        elif form.is_valid():
            user = form.save()
            try:
                profile = user.profile
                profile.must_change_password = False
                profile.save(update_fields=["must_change_password"])
            except Exception:
                logger.debug("no profile to clear must_change_password", exc_info=True)
            update_session_auth_hash(request, user)
            messages.success(request, "Password changed.")
            return redirect("mvp:dashboard")
    else:
        form = PasswordChangeForm(request.user)
    return render(request, "mvp/change_password.html", {"form": form})
