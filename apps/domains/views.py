from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
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
        domain.delete()
    return redirect("domain-list")
