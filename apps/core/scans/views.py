"""Django views for OpenEASD scan management."""

import datetime
import logging
import threading

from django.db import models
from django.db.models import Count, Max
from django.core.paginator import Paginator
from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required

from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger

from .forms import StartScanForm
from .models import ScanSession
from .tasks import run_scan, run_scheduled_scan

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = ["critical", "high", "medium", "low"]
BUILTIN_JOB_IDS = {"daily_scan", "watchdog_reap_stuck_scans"}


def _get_vuln_counts(session):
    """Aggregate finding counts by severity — single query."""
    counts = {sev: 0 for sev in SEVERITY_LEVELS}
    try:
        rows = (
            session.domain_findings
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

    job_id = f"once_{domain}_{scheduled_at.strftime('%Y%m%d%H%M')}"
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
    if request.method == "POST":
        prefilled_domain = request.POST.get("domain", "").strip()
        form = StartScanForm(request.POST)
        if form.is_valid():
            domain = form.cleaned_data["domain"].strip()
            schedule_type = form.cleaned_data["schedule_type"]

            if schedule_type == "now":
                from .tasks import create_scan_session
                session = create_scan_session(domain)
                if session is None:
                    form.add_error("domain", f"A scan for {domain} is already running. Please wait for it to finish.")
                else:
                    threading.Thread(target=run_scan, args=[session.id], daemon=True).start()
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

    return render(request, "scans/detail.html", {
        "session": session,
        "vuln_counts": vuln_counts,
    })


@login_required
def scan_status_fragment(request, session_uuid):
    session = get_object_or_404(ScanSession, uuid=session_uuid)
    vuln_counts = _get_vuln_counts(session)

    response = render(request, "partials/scan_status.html", {
        "session": session,
        "vuln_counts": vuln_counts,
    })

    if session.status != "running":
        response["HX-Trigger"] = "scanComplete"

    return response


def _latest_session_ids():
    """Return the ID of the latest completed scan session per domain."""
    rows = (
        ScanSession.objects
        .filter(status="completed")
        .values("domain")
        .annotate(latest_id=Max("id"))
    )
    return [r["latest_id"] for r in rows]


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
        # Format: once_{domain}_{YYYYMMDDHHmm} — strip prefix and 13-char timestamp suffix
        suffix = job.id[len("once_"):]
        domain = suffix[:-13] if len(suffix) > 13 else suffix
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
    from apps.domain_security.models import DomainFinding

    severity = request.GET.get("severity", "").strip()
    domain = request.GET.get("domain", "").strip()
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
        return qs

    # Default: restrict to latest completed session per domain (no duplicates across runs)
    base_qs = DomainFinding.objects.select_related("session")
    if not session_id:
        base_qs = base_qs.filter(session_id__in=_latest_session_ids())

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
        {"source": f.check_type, "severity": f.severity, "title": f.title,
         "host": f.domain, "session": f.session, "obj": f}
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
    })
