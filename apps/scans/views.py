"""Django views for OpenEASD scan management."""

import logging
import threading

from django.db import models
from django.db.models import Q
from django.core.paginator import Paginator
from django.shortcuts import render, get_object_or_404, redirect
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required

from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger

from .forms import StartScanForm
from .models import ScanSession
from .tasks import run_scan

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = ["critical", "high", "medium", "low"]


def _get_vuln_counts(session):
    """Aggregate finding counts by severity — single query."""
    from django.db.models import Count
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
        pass
    return counts


def _schedule_once(domain, scheduled_at):
    """Schedule a one-time scan using the shared persistent scheduler."""
    from apps.core.scheduler import get_scheduler

    def _run():
        session = ScanSession.objects.create(domain=domain, scan_type="full")
        run_scan(session.id)

    job_id = f"once_{domain}_{scheduled_at.strftime('%Y%m%d%H%M')}"
    get_scheduler().add_job(
        _run,
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

    def _run():
        session = ScanSession.objects.create(domain=domain, scan_type="full")
        run_scan(session.id)

    if recurrence == "weekly":
        trigger = CronTrigger(day_of_week="mon", hour=recurrence_time.hour, minute=recurrence_time.minute)
    else:
        trigger = CronTrigger(hour=recurrence_time.hour, minute=recurrence_time.minute)

    job_id = f"recurring_{domain}"
    get_scheduler().add_job(
        _run,
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
                from .tasks import _is_scan_active
                if _is_scan_active(domain):
                    form.add_error("domain", f"A scan for {domain} is already running. Please wait for it to finish.")
                else:
                    session = ScanSession.objects.create(domain=domain, scan_type="full", status="pending")
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

    return render(request, "scans/list.html", {
        "scans": page,
        "domain": domain,
        "status_filter": status_filter,
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


@login_required
def vulnerability_list(request):
    """Aggregate view across all finding types."""
    from apps.domain_security.models import DomainFinding

    severity = request.GET.get("severity", "").strip()
    session_id = request.GET.get("session_id", "").strip()
    domain = request.GET.get("domain", "").strip()

    def _filter(qs):
        if severity:
            qs = qs.filter(severity=severity)
        if session_id:
            qs = qs.filter(session_id=session_id)
        if domain:
            qs = qs.filter(session__domain__icontains=domain)
        return qs

    qs = _filter(
        DomainFinding.objects
        .select_related("session")
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

    return render(request, "vulnerabilities/list.html", {
        "vulns": vulns,
        "page_obj": page,
        "severity": severity,
        "session_id": session_id,
        "domain": domain,
    })
