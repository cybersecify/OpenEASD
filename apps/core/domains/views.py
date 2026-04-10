import logging

from django.db import transaction
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required

logger = logging.getLogger(__name__)

from apps.core.scans.models import ScanSession
from apps.core.insights.models import ScanSummary
from .models import Domain
from .forms import DomainForm


@login_required
def domain_list(request):
    if request.method == "POST":
        form = DomainForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("domain-list")
    else:
        form = DomainForm()

    domains = Domain.objects.all()

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
                domains = Domain.objects.all()
                form = DomainForm()
                return render(request, "domains/list.html", {
                    "domains": domains,
                    "form": form,
                    "delete_error": f"Cannot delete '{domain_name}' — a scan is currently active. Wait for it to finish.",
                })
            ScanSession.objects.filter(domain=domain_name).delete()
            ScanSummary.objects.filter(domain=domain_name).delete()
            domain.delete()
    return redirect("domain-list")
