"""Issues API — ``/api/issues/`` : the persistent, cross-scan finding register.

Reads and triages the ``Issue`` register (``apps/core/data/findings/models.Issue``).
A status change here **persists across scans** (unlike per-scan
``Finding.status``) — that is the point of the finding-centric UI: dismiss a false
positive once and it stays dismissed. Spec:
docs/specs/2026-09-12-finding-centric-ui-direction.md (PR3).
"""

import logging

from django.core.paginator import Paginator
from django.db.models import Case, Count, IntegerField, Value, When
from django.shortcuts import get_object_or_404
from ninja import Router, Schema
from ninja.errors import HttpError

from apps.core.console.api.auth import JWTAuth
from apps.core.constants import SEVERITY_RANK

from .models import STATUS_CHOICES, Issue

logger = logging.getLogger(__name__)
router = Router(auth=JWTAuth())

_VALID_STATUSES = {s for s, _ in STATUS_CHOICES}
# Issues that still need attention (drives the default view + the severity summary).
_ACTIONABLE = ("open", "acknowledged", "in_progress")


class StatusIn(Schema):
    status: str


def _row(i) -> dict:
    return {
        "id": i.id,
        "domain": i.domain.name,
        "source": i.source,
        "check_type": i.check_type,
        "title": i.title,
        "target": i.target,
        "severity": i.severity,
        "status": i.status,
        "first_seen": i.first_seen.isoformat(),
        "last_seen": i.last_seen.isoformat(),
        "asset_id": i.asset_id,
    }


def _ranked(qs):
    """Order most-severe-first, then most-recent — using the shared SEVERITY_RANK
    so the register's ranking can't drift from the rest of the app."""
    whens = [When(severity=s, then=Value(r)) for s, r in SEVERITY_RANK.items()]
    return qs.annotate(
        sev_rank=Case(*whens, default=Value(-1), output_field=IntegerField())
    ).order_by("-sev_rank", "-last_seen")


@router.get("/")
def list_issues(request, domain: str = "", status: str = "", severity: str = "",
                source: str = "", q: str = "", page: int = 1):
    qs = Issue.objects.select_related("domain")
    if domain:
        qs = qs.filter(domain__name__icontains=domain)
    if status:
        qs = qs.filter(status=status)
    if severity:
        qs = qs.filter(severity=severity)
    if source:
        qs = qs.filter(source=source)
    if q:
        qs = qs.filter(title__icontains=q)

    paginator = Paginator(_ranked(qs), 25)
    p = paginator.get_page(page)
    return {
        "issues": [_row(i) for i in p],
        "total": paginator.count,
        "page": p.number,
        "total_pages": paginator.num_pages,
        "has_next": p.has_next(),
        "has_previous": p.has_previous(),
    }


@router.get("/summary/")
def issues_summary(request, domain: str = ""):
    qs = Issue.objects.all()
    if domain:
        qs = qs.filter(domain__name__icontains=domain)

    by_status = {s: 0 for s, _ in STATUS_CHOICES}
    for row in qs.values("status").annotate(n=Count("id")):
        by_status[row["status"]] = row["n"]

    # Severity breakdown of the still-actionable issues (open/ack/in-progress) —
    # what actually needs work, excluding resolved / dismissed.
    open_by_severity: dict[str, int] = {}
    for row in (qs.filter(status__in=_ACTIONABLE)
                  .values("severity").annotate(n=Count("id"))):
        open_by_severity[row["severity"]] = row["n"]

    return {
        "total": qs.count(),
        "by_status": by_status,
        "open_by_severity": open_by_severity,
    }


@router.post("/{issue_id}/status/")
def set_issue_status(request, issue_id: int, data: StatusIn):
    if data.status not in _VALID_STATUSES:
        raise HttpError(400, f"status must be one of {sorted(_VALID_STATUSES)}")
    issue = get_object_or_404(Issue, id=issue_id)
    issue.status = data.status
    issue.save(update_fields=["status"])
    logger.info("[issues] %s → %s", issue_id, data.status)
    return _row(issue)
