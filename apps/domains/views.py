from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required

from apps.scans.models import ScanSession
from apps.insights.models import ScanSummary
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
    return render(request, "domains/list.html", {"domains": domains, "form": form})


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
        # Delete all scan data for this domain (ScanSession cascades to findings)
        ScanSession.objects.filter(domain=domain_name).delete()
        ScanSummary.objects.filter(domain=domain_name).delete()
        domain.delete()
    return redirect("domain-list")
