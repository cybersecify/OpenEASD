"""Domains API router."""

import logging

from django.db import transaction
from django.db.models import Count
from django.shortcuts import get_object_or_404

from ninja import Router, Schema, Status
from ninja.errors import HttpError

from apps.core.api.auth import auth_bearer
from apps.core.domains.models import Domain
from apps.core.findings.models import Finding
from apps.core.insights.builder import _rebuild_finding_type_summaries
from apps.core.insights.models import ScanSummary
from apps.core.queries import latest_session_ids
from apps.core.scans.models import ScanSession

logger = logging.getLogger(__name__)

router = Router(auth=auth_bearer)


def _enrich_domains(domains):
    """Attach last_scan and findings_summary to each Domain object in-place."""
    domain_names = [d.name for d in domains]
    if not domain_names:
        return

    latest_sessions = {}
    for session in ScanSession.objects.filter(domain__in=domain_names).order_by(
        "domain", "-start_time"
    ):
        if session.domain not in latest_sessions:
            latest_sessions[session.domain] = session

    latest_ids = latest_session_ids(domains=domain_names)
    findings_by_domain = {}
    if latest_ids:
        for row in (
            Finding.objects.filter(session_id__in=latest_ids, status="open")
            .exclude(severity="info")
            .values("session__domain", "severity")
            .annotate(count=Count("id"))
        ):
            d = row["session__domain"]
            findings_by_domain.setdefault(d, {})[row["severity"]] = row["count"]

    for domain in domains:
        domain.last_scan = latest_sessions.get(domain.name)
        domain.findings_summary = findings_by_domain.get(domain.name, {})


def _serialize_domain(domain) -> dict:
    last_scan = getattr(domain, "last_scan", None)
    last_scan_data = None
    if last_scan is not None:
        last_scan_data = {
            "id": last_scan.id,
            "uuid": str(last_scan.uuid),
            "domain_name": last_scan.domain,
            "status": last_scan.status,
            "start_time": last_scan.start_time.isoformat(),
            "end_time": last_scan.end_time.isoformat() if last_scan.end_time else None,
            "total_findings": last_scan.total_findings,
        }
    return {
        "id": domain.id,
        "name": domain.name,
        "is_primary": domain.is_primary,
        "is_active": domain.is_active,
        "added_at": domain.added_at.isoformat() if domain.added_at else None,
        "last_scan": last_scan_data,
        "findings_summary": getattr(domain, "findings_summary", {}),
    }


class DomainIn(Schema):
    name: str


@router.get("/")
def list_domains(request):
    domains = list(Domain.objects.all())
    _enrich_domains(domains)
    return [_serialize_domain(d) for d in domains]


@router.post("/", response={201: dict})
def create_domain(request, data: DomainIn):
    name = data.name.strip()
    if not name:
        raise HttpError(400, "Name is required")
    if Domain.objects.filter(name=name).exists():
        raise HttpError(400, "Domain already exists")
    domain = Domain.objects.create(name=name)
    domain.last_scan = None
    domain.findings_summary = {}
    return Status(201, _serialize_domain(domain))


@router.post("/{pk}/toggle/")
def toggle_domain(request, pk: int):
    domain = get_object_or_404(Domain, pk=pk)
    domain.is_active = not domain.is_active
    domain.save()
    _enrich_domains([domain])
    return _serialize_domain(domain)


@router.post("/{pk}/delete/")
def delete_domain(request, pk: int):
    domain = get_object_or_404(Domain, pk=pk)
    domain_name = domain.name

    active = ScanSession.objects.filter(
        domain=domain_name, status__in=["pending", "running"]
    ).exists()
    if active:
        raise HttpError(409, "Cannot delete — a scan is currently active.")

    with transaction.atomic():
        ScanSession.objects.filter(domain=domain_name).delete()
        ScanSummary.objects.filter(domain=domain_name).delete()
        domain.delete()

    _rebuild_finding_type_summaries()
    return {"deleted": domain_name}
