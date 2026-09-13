"""Findings API — ``/api/findings/`` : raw per-scan Finding instances.

These are the per-scan ``Finding`` rows (finding-centric list + per-finding
lifecycle status). Distinct from ``/api/issues/`` (the ``issues`` app), which is
the deduped, cross-scan persistent register those findings are promoted into.
Relocated here from ``/api/scans/findings/`` (D-017).
"""

import logging
import uuid

from django.core.paginator import Paginator
from django.db.models import Case, IntegerField, When
from django.shortcuts import get_object_or_404
from ninja import Router, Schema
from ninja.errors import HttpError

from apps.core.console.api.auth import JWTAuth

from .models import STATUS_CHOICES

logger = logging.getLogger(__name__)
router = Router(auth=JWTAuth())

_VALID_STATUSES = {s for s, _ in STATUS_CHOICES}


def _serialize_finding(finding) -> dict:
    return {
        "id": finding.id,
        "session_id": finding.session_id,
        "session_uuid": str(finding.session.uuid) if finding.session else None,
        "source": finding.source,
        "check_type": finding.check_type,
        "severity": finding.severity,
        "title": finding.title,
        "description": finding.description,
        "remediation": finding.remediation,
        "target": finding.target,
        "asset_id": finding.asset_id,
        "asset_key": finding.asset.key if finding.asset_id else None,
        "asset_kind": finding.asset.kind if finding.asset_id else None,
        "extra": finding.extra,
        "discovered_at": finding.discovered_at.isoformat(),
        "status": finding.status,
        "assigned_to": finding.assigned_to,
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
        "resolution_note": finding.resolution_note,
    }


class FindingStatusRequest(Schema):
    status: str
    assigned_to: str | None = None
    resolution_note: str | None = None


@router.get("/")
def list_findings(
    request,
    severity: str = "",
    domain: str = "",
    status: str = "",
    source: str = "",
    session_id: int = 0,
    session_uuid: uuid.UUID | None = None,
    page: int = 1,
):
    from apps.core.data.findings.models import Finding
    from apps.core.engine.scans.models import ScanSession
    from apps.core.queries import latest_session_ids

    if session_uuid is not None and not session_id:
        session = get_object_or_404(ScanSession, uuid=str(session_uuid))
        session_id = session.id

    latest_ids = latest_session_ids()
    base_qs = Finding.objects.select_related("session", "asset")
    if not session_id:
        base_qs = base_qs.filter(session_id__in=latest_ids)

    if session_id:
        count_base = Finding.objects.filter(session_id=session_id, status="open")
    else:
        count_base = Finding.objects.filter(session_id__in=latest_ids, status="open")
    count_open_critical = count_base.filter(severity="critical").count()
    count_open_high     = count_base.filter(severity="high").count()
    count_open_medium   = count_base.filter(severity="medium").count()
    count_open_low      = count_base.filter(severity="low").count()

    qs = base_qs.order_by(
        Case(
            When(severity="critical", then=0),
            When(severity="high", then=1),
            When(severity="medium", then=2),
            When(severity="low", then=3),
            default=4,
            output_field=IntegerField(),
        ),
        "-discovered_at",
    )

    if severity:
        qs = qs.filter(severity=severity)
    if session_id:
        qs = qs.filter(session_id=session_id)
    if domain:
        qs = qs.filter(session__domain__icontains=domain)
    if status:
        qs = qs.filter(status=status)
    if source:
        qs = qs.filter(source=source)

    paginator = Paginator(qs, 25)
    p = paginator.get_page(page)

    return {
        "findings": [_serialize_finding(f) for f in p],
        "counts": {
            "open_critical": count_open_critical,
            "open_high": count_open_high,
            "open_medium": count_open_medium,
            "open_low": count_open_low,
        },
        "total": paginator.count,
        "page": p.number,
        "total_pages": paginator.num_pages,
        "has_next": p.has_next(),
        "has_previous": p.has_previous(),
    }


@router.post("/{finding_id}/status/")
def update_finding_status(request, finding_id: int, data: FindingStatusRequest):
    from django.utils import timezone

    from apps.core.data.findings.models import Finding

    finding = get_object_or_404(Finding, id=finding_id)

    if data.status not in _VALID_STATUSES:
        raise HttpError(400, f"status must be one of: {', '.join(sorted(_VALID_STATUSES))}")

    finding.status = data.status
    if data.status == "resolved" and not finding.resolved_at:
        finding.resolved_at = timezone.now()
    elif data.status != "resolved":
        finding.resolved_at = None

    if data.assigned_to is not None:
        finding.assigned_to = str(data.assigned_to)[:150]
    if data.resolution_note is not None:
        finding.resolution_note = str(data.resolution_note)[:5000]

    finding.save(update_fields=["status", "resolved_at", "assigned_to", "resolution_note"])
    return _serialize_finding(finding)
