"""Django views for OpenEASD scan management."""

import datetime
import logging
import uuid

from django.db import models
from django.db.models import Count, Q
from django.core.paginator import Paginator
from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required

from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger

from apps.core.constants import SEVERITY_LEVELS
from apps.core.queries import latest_session_ids

from .forms import StartScanForm
from .models import ScanSession
from apps.core.scheduler.scheduler import run_scheduled_scan

logger = logging.getLogger(__name__)
BUILTIN_JOB_IDS = {"daily_scan", "watchdog_reap_stuck_scans"}


def _get_vuln_counts(session):
    """Aggregate finding counts by severity — single query."""
    from apps.core.findings.models import Finding

    counts = {sev: 0 for sev in SEVERITY_LEVELS}
    try:
        rows = (
            Finding.objects
            .filter(session=session)
            .values("severity")
            .annotate(total=Count("id"))
        )
        for row in rows:
            if row["severity"] in counts:
                counts[row["severity"]] = row["total"]
    except Exception:
        logger.exception(f"[_get_vuln_counts] Failed to aggregate findings for session {session.id}")
    return counts


def _schedule_once(domain, scheduled_at):
    """Schedule a one-time scan using the shared persistent scheduler."""
    from apps.core.scheduler import get_scheduler

    job_id = f"once_{domain}_{uuid.uuid4().hex}"
    get_scheduler().add_job(
        run_scheduled_scan,
        args=[domain, "scheduled"],
        trigger=DateTrigger(run_date=scheduled_at),
        id=job_id,
        name=f"One-time scan: {domain}",
        jobstore="default",
        replace_existing=True,
        misfire_grace_time=3600,
    )
    logger.info(f"One-time scan scheduled: domain={domain} at={scheduled_at}")


def _schedule_recurring(domain, recurrence, recurrence_time):
    """Add or replace a recurring scan job using the shared persistent scheduler."""
    from apps.core.scheduler import get_scheduler

    if recurrence == "weekly":
        trigger = CronTrigger(day_of_week="mon", hour=recurrence_time.hour, minute=recurrence_time.minute)
    else:
        trigger = CronTrigger(hour=recurrence_time.hour, minute=recurrence_time.minute)

    job_id = f"recurring_{domain}"
    get_scheduler().add_job(
        run_scheduled_scan,
        args=[domain, "recurring"],
        trigger=trigger,
        id=job_id,
        name=f"Recurring {recurrence} scan: {domain}",
        jobstore="default",
        replace_existing=True,
        misfire_grace_time=3600,
    )
    logger.info(f"Recurring scan scheduled: domain={domain} recurrence={recurrence} time={recurrence_time}")


@login_required
@require_http_methods(["GET", "POST"])
def scan_start(request):
    from apps.core.domains.models import Domain

    # Block scanning entirely until at least one active domain exists
    if not Domain.objects.filter(is_active=True).exists():
        return render(request, "scans/start.html", {
            "form": None,
            "no_domains": True,
            "prefilled_domain": "",
        })

    if request.method == "POST":
        prefilled_domain = request.POST.get("domain", "").strip()
        form = StartScanForm(request.POST)
        if form.is_valid():
            domain = form.cleaned_data["domain"].strip()
            schedule_type = form.cleaned_data["schedule_type"]

            if schedule_type == "now":
                from .pipeline import create_scan_session
                workflow = form.cleaned_data.get("workflow")
                session = create_scan_session(domain, workflow=workflow)
                if session is None:
                    form.add_error("domain", f"A scan for {domain} is already running. Please wait for it to finish.")
                else:
                    from .tasks import run_scan_task
                    run_scan_task(session.id)
                    logger.info(f"Scan started: session={session.id} domain={domain}")
                    return redirect("scan-detail", session_uuid=session.uuid)

            elif schedule_type == "once":
                scheduled_at = form.cleaned_data["scheduled_at"]
                _schedule_once(domain, scheduled_at)
                return redirect("domain-list")

            elif schedule_type == "recurring":
                recurrence = form.cleaned_data["recurrence"]
                recurrence_time = form.cleaned_data["recurrence_time"]
                _schedule_recurring(domain, recurrence, recurrence_time)
                return redirect("domain-list")
    else:
        prefilled_domain = request.GET.get("domain", "").strip()
        form = StartScanForm(initial={"domain": prefilled_domain})

    return render(request, "scans/start.html", {"form": form, "prefilled_domain": prefilled_domain})


@login_required
def scan_list(request):
    qs = ScanSession.objects.all()

    domain = request.GET.get("domain", "").strip()
    status_filter = request.GET.get("status", "").strip()

    if domain:
        qs = qs.filter(domain__icontains=domain)
    if status_filter:
        qs = qs.filter(status=status_filter)

    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get("page"))

    if request.htmx:
        return render(request, "partials/scan_rows.html", {"scans": page})

    # Scheduled jobs for inline display
    from apps.core.scheduler import get_scheduler
    scheduled = []
    try:
        scheduled = [p for job in get_scheduler().get_jobs() if (p := _parse_job(job)) is not None]
        scheduled.sort(key=lambda j: (
            0 if j["job_type"] == "recurring" else 1,
            j["next_run_time"] or datetime.datetime.max.replace(tzinfo=datetime.timezone.utc),
        ))
    except Exception:
        logger.exception("[scan_list] Failed to fetch scheduled jobs")

    return render(request, "scans/list.html", {
        "scans": page,
        "domain": domain,
        "status_filter": status_filter,
        "scheduled": scheduled,
    })


@login_required
def scan_detail(request, session_uuid):
    session = get_object_or_404(ScanSession, uuid=session_uuid)
    vuln_counts = _get_vuln_counts(session)

    from apps.core.assets.models import Subdomain, IPAddress, Port
    from apps.core.web_assets.models import URL
    from apps.core.findings.models import Finding

    subdomains = list(Subdomain.objects.filter(session=session).order_by("-is_active", "subdomain"))
    ips = list(IPAddress.objects.filter(session=session).select_related("subdomain").order_by("address"))
    ports = list(Port.objects.filter(session=session).select_related("ip_address").order_by("address", "port"))
    urls = list(URL.objects.filter(session=session).select_related("port", "subdomain").order_by("url"))
    nmap_findings = list(Finding.objects.filter(session=session, source="nmap").select_related("port").order_by("-discovered_at"))
    domain_findings = list(Finding.objects.filter(session=session, source="domain_security").select_related("subdomain").order_by("-severity", "-discovered_at"))

    return render(request, "scans/detail.html", {
        "session": session,
        "vuln_counts": vuln_counts,
        "live_total": sum(vuln_counts.values()),
        "subdomains": subdomains,
        "ips": ips,
        "ports": ports,
        "urls": urls,
        "nmap_findings": nmap_findings,
        "domain_findings": domain_findings,
        "asset_counts": {
            "subdomains_total": len(subdomains),
            "subdomains_active": sum(1 for s in subdomains if s.is_active),
            "ips": len(ips),
            "ports": len(ports),
            "urls": len(urls),
            "nmap_findings": len(nmap_findings),
        },
    })


@login_required
def scan_status_fragment(request, session_uuid):
    session = get_object_or_404(ScanSession, uuid=session_uuid)
    vuln_counts = _get_vuln_counts(session)

    from apps.core.assets.models import Subdomain, IPAddress, Port
    from apps.core.web_assets.models import URL
    from apps.core.findings.models import Finding

    sub_agg = Subdomain.objects.filter(session=session).aggregate(
        total=Count("id"),
        active=Count("id", filter=Q(is_active=True)),
    )
    asset_counts = {
        "subdomains_total":  sub_agg["total"],
        "subdomains_active": sub_agg["active"],
        "ips":               IPAddress.objects.filter(session=session).count(),
        "ports":             Port.objects.filter(session=session).count(),
        "urls":              URL.objects.filter(session=session).count(),
        "nmap_findings":     Finding.objects.filter(session=session, source="nmap").count(),
    }

    # Workflow step progress
    step_results = []
    try:
        run = session.workflow_run
        step_results = list(run.step_results.order_by("order"))
    except Exception:
        pass

    response = render(request, "partials/scan_status.html", {
        "live_total": sum(vuln_counts.values()),
        "session": session,
        "vuln_counts": vuln_counts,
        "asset_counts": asset_counts,
        "step_results": step_results,
    })

    if session.status not in ("running", "pending"):
        response["HX-Trigger"] = "scanComplete"

    return response


@login_required
@require_http_methods(["POST"])
def scan_stop(request, session_uuid):
    """Cancel a running scan. The workflow runner checks for this between steps."""
    session = get_object_or_404(ScanSession, uuid=session_uuid)
    if session.status in ("pending", "running"):
        from django.utils import timezone as django_tz
        session.status = "cancelled"
        session.end_time = django_tz.now()
        session.save(update_fields=["status", "end_time"])
        logger.info(f"Scan cancelled: session={session.id} domain={session.domain}")
    return redirect("scan-detail", session_uuid=session.uuid)


def _describe_cron_trigger(trigger):
    try:
        for field in trigger.fields:
            if field.name == "day_of_week" and not field.is_default:
                return "Weekly (Mondays)"
        return "Daily"
    except Exception:
        return "Recurring"


def _parse_job(job):
    """Convert APScheduler job → dict for template. Returns None for built-in jobs."""
    if job.id in BUILTIN_JOB_IDS:
        return None
    if job.id.startswith("recurring_"):
        domain = job.id[len("recurring_"):]
        job_type = "recurring"
        frequency = _describe_cron_trigger(job.trigger)
    elif job.id.startswith("once_"):
        # Format: once_{domain}_{32-char uuid hex} — strip prefix and 33-char suffix
        suffix = job.id[len("once_"):]
        domain = suffix[:-33] if len(suffix) > 33 else suffix
        job_type = "one-time"
        frequency = "—"
    else:
        domain = job.name
        job_type = "unknown"
        frequency = "—"
    return {
        "job_id": job.id,
        "domain": domain,
        "job_type": job_type,
        "next_run_time": job.next_run_time,
        "frequency": frequency,
    }


@login_required
@require_http_methods(["GET"])
def scheduled_jobs(request):
    """List all user-created scheduled scan jobs."""
    from apps.core.scheduler import get_scheduler
    try:
        all_jobs = get_scheduler().get_jobs()
    except Exception:
        logger.exception("[scheduled_jobs] Failed to fetch jobs from scheduler")
        all_jobs = []
    jobs = [p for job in all_jobs if (p := _parse_job(job)) is not None]
    jobs.sort(key=lambda j: (
        0 if j["job_type"] == "recurring" else 1,
        j["next_run_time"] or datetime.datetime.max.replace(tzinfo=datetime.timezone.utc),
    ))
    return render(request, "scans/scheduled.html", {"jobs": jobs})


@login_required
@require_http_methods(["POST"])
def cancel_scheduled_job(request, job_id):
    """Remove a user-created scheduled job from APScheduler."""
    from apps.core.scheduler import get_scheduler
    from apscheduler.jobstores.base import JobLookupError

    if job_id in BUILTIN_JOB_IDS or not (job_id.startswith("once_") or job_id.startswith("recurring_")):
        return redirect("scan-list")

    try:
        get_scheduler().remove_job(job_id)
        logger.info(f"Scheduled job cancelled: {job_id}")
    except JobLookupError:
        logger.info(f"Job already gone (may have already run): {job_id}")

    return redirect("scan-list")


@login_required
def vulnerability_list(request):
    """Show findings from the latest completed scan per domain only."""
    from apps.core.findings.models import Finding, STATUS_CHOICES

    severity = request.GET.get("severity", "").strip()
    domain = request.GET.get("domain", "").strip()
    status_filter = request.GET.get("status", "").strip()
    raw_session_id = request.GET.get("session_id", "").strip()
    try:
        session_id = int(raw_session_id) if raw_session_id else None
    except ValueError:
        session_id = None

    def _filter(qs):
        if severity:
            qs = qs.filter(severity=severity)
        if session_id:
            qs = qs.filter(session_id=session_id)
        if domain:
            qs = qs.filter(session__domain__icontains=domain)
        if status_filter:
            qs = qs.filter(status=status_filter)
        return qs

    # Default: restrict to latest completed session per domain (no duplicates across runs)
    base_qs = Finding.objects.select_related("session")
    if not session_id:
        base_qs = base_qs.filter(session_id__in=latest_session_ids())

    qs = _filter(
        base_qs
        .order_by(
            # severity desc via CASE ordering
            models.Case(
                models.When(severity="critical", then=0),
                models.When(severity="high", then=1),
                models.When(severity="medium", then=2),
                models.When(severity="low", then=3),
                default=4,
                output_field=models.IntegerField(),
            ),
            "-discovered_at",
        )
    )

    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get("page"))

    vulns = [
        {"source": f.source, "severity": f.severity, "title": f.title,
         "host": f.target or f.session.domain, "session": f.session, "obj": f}
        for f in page
    ]

    if request.htmx:
        return render(request, "partials/vuln_rows.html", {"vulns": vulns})

    return render(request, "findings/list.html", {
        "vulns": vulns,
        "page_obj": page,
        "severity": severity,
        "session_id": session_id,
        "domain": domain,
        "status_filter": status_filter,
        "status_choices": STATUS_CHOICES,
    })


@login_required
@require_http_methods(["POST"])
def finding_update_status(request, finding_id):
    """Update finding lifecycle status (HTMX inline edit)."""
    from apps.core.findings.models import Finding, STATUS_CHOICES
    from django.http import HttpResponseBadRequest
    from django.utils import timezone

    finding = get_object_or_404(Finding, id=finding_id)
    new_status = request.POST.get("status", "").strip()
    valid_statuses = {s[0] for s in STATUS_CHOICES}
    if new_status not in valid_statuses:
        return HttpResponseBadRequest("Invalid status")

    finding.status = new_status
    if new_status == "resolved" and not finding.resolved_at:
        finding.resolved_at = timezone.now()
    elif new_status != "resolved":
        finding.resolved_at = None

    finding.assigned_to = request.POST.get("assigned_to", finding.assigned_to)[:150]
    finding.resolution_note = request.POST.get("resolution_note", finding.resolution_note)[:5000]
    finding.save(update_fields=["status", "resolved_at", "assigned_to", "resolution_note"])

    return render(request, "partials/finding_status_cell.html", {
        "finding": finding,
        "status_choices": STATUS_CHOICES,
    })
