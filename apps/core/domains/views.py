import logging

from django.contrib import messages
from django.db import transaction
from django.db.models import Count
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required

logger = logging.getLogger(__name__)

from apps.core.scans.models import ScanSession
from apps.core.insights.models import ScanSummary
from apps.core.queries import latest_session_ids
from apps.core.findings.models import Finding
from .models import Domain
from .forms import DomainForm


def _enrich_domains(domains):
    """Attach last_scan and findings_summary to each Domain object in-place."""
    domain_names = [d.name for d in domains]
    if not domain_names:
        return

    # Latest session per domain (any status) — for Last Scan column
    latest_sessions = {}
    for session in ScanSession.objects.filter(
        domain__in=domain_names
    ).order_by("domain", "-start_time"):
        if session.domain not in latest_sessions:
            latest_sessions[session.domain] = session

    # Open findings from latest completed session — for Findings column
    latest_ids = latest_session_ids(domains=domain_names)
    findings_by_domain = {}
    if latest_ids:
        for row in (
            Finding.objects
            .filter(session_id__in=latest_ids, status="open")
            .exclude(severity="info")
            .values("session__domain", "severity")
            .annotate(count=Count("id"))
        ):
            d = row["session__domain"]
            findings_by_domain.setdefault(d, {})[row["severity"]] = row["count"]

    for domain in domains:
        domain.last_scan = latest_sessions.get(domain.name)
        domain.findings_summary = findings_by_domain.get(domain.name, {})


@login_required
def domain_list(request):
    if request.method == "POST":
        form = DomainForm(request.POST)
        if form.is_valid():
            domain = form.save()
            messages.success(request, f"Domain {domain.name} added successfully.")
            return redirect("domain-list")
    else:
        form = DomainForm()

    domains = list(Domain.objects.all())
    _enrich_domains(domains)

    recurring_domains = set()
    try:
        from apps.core.scheduler import get_scheduler
        for job in get_scheduler().get_jobs():
            if job.id.startswith("recurring_"):
                recurring_domains.add(job.id[len("recurring_"):])
    except Exception:
        logger.exception("[domain_list] Failed to fetch recurring scheduled jobs")

    return render(request, "domains/list.html", {
        "domains": domains,
        "form": form,
        "recurring_domains": recurring_domains,
    })


@login_required
def domain_toggle(request, pk):
    domain = get_object_or_404(Domain, pk=pk)
    domain.is_active = not domain.is_active
    domain.save()
    status = "activated" if domain.is_active else "paused"
    messages.success(request, f"Domain {domain.name} {status}.")
    return redirect("domain-list")


@login_required
def domain_delete(request, pk):
    domain = get_object_or_404(Domain, pk=pk)
    if request.method == "POST":
        domain_name = domain.name
        with transaction.atomic():
            active = ScanSession.objects.filter(
                domain=domain_name, status__in=["pending", "running"]
            ).exists()
            if active:
                domains = list(Domain.objects.all())
                _enrich_domains(domains)
                form = DomainForm()
                return render(request, "domains/list.html", {
                    "domains": domains,
                    "form": form,
                    "delete_error": f"Cannot delete '{domain_name}' — a scan is currently active. Wait for it to finish.",
                })
            ScanSession.objects.filter(domain=domain_name).delete()
            ScanSummary.objects.filter(domain=domain_name).delete()
            domain.delete()
            from apps.core.insights.builder import _rebuild_finding_type_summaries
            _rebuild_finding_type_summaries()
            messages.success(request, f"Domain {domain_name} and all its scan data deleted.")
    return redirect("domain-list")
