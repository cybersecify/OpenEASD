"""Asset inventory API — /api/assets/ (spec: docs/specs/2026-09-06-asset-centric-inventory.md, PR2).

Read-only views over the persistent Asset inventory built by the finalize
rollup. Flat JSON, JWT-authed, same shape/pagination as the rest of the API.
"""

import logging

from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from ninja import Router

from apps.core.api.auth import JWTAuth

from .models import Asset

logger = logging.getLogger(__name__)

router = Router(auth=JWTAuth())

_SEV = ["critical", "high", "medium", "low", "info"]


def _severity_counts():
    """Conditional-aggregation annotations: open findings per severity, per asset."""
    return {
        f"c_{s}": Count("findings", filter=Q(findings__severity=s, findings__status="open"))
        for s in _SEV
    }


def _row(a) -> dict:
    return {
        "id": a.id,
        "kind": a.kind,
        "key": a.key,
        "domain": a.domain.name,
        "status": a.status,
        "first_seen": a.first_seen.isoformat(),
        "last_seen": a.last_seen.isoformat(),
        "findings": {s: getattr(a, f"c_{s}", 0) for s in _SEV},
    }


def _finding_brief(f) -> dict:
    return {
        "id": f.id,
        "session_uuid": str(f.session.uuid) if f.session_id else None,
        "source": f.source,
        "check_type": f.check_type,
        "severity": f.severity,
        "title": f.title,
        "target": f.target,
        "status": f.status,
        "discovered_at": f.discovered_at.isoformat(),
    }


def _seen_in_scans(asset) -> list[dict]:
    """Best-effort scan timeline: sessions whose per-scan assets carried this key.

    PR1 has no AssetObservation table, so this derives the timeline from the
    session-scoped asset rows. Guarded — any parse/lookup issue yields []."""
    from apps.core.scans.models import ScanSession

    dn = asset.domain.name
    try:
        if asset.kind == "subdomain":
            from apps.core.assets.models import Subdomain
            sids = Subdomain.objects.filter(session__domain=dn, subdomain=asset.key)
        elif asset.kind == "ip":
            from apps.core.assets.models import IPAddress
            sids = IPAddress.objects.filter(session__domain=dn, address=asset.key)
        elif asset.kind == "port":
            from apps.core.assets.models import Port
            addr, rest = asset.key.rsplit(":", 1)
            port_num, proto = rest.split("/")
            sids = Port.objects.filter(
                session__domain=dn, address=addr, port=int(port_num), protocol=proto
            )
        elif asset.kind == "url":
            from apps.core.web_assets.models import URL
            sids = URL.objects.filter(session__domain=dn, url=asset.key)
        else:
            return []
        session_ids = set(sids.values_list("session_id", flat=True))
    except Exception:  # noqa: BLE001 — timeline is best-effort, never fail the request
        logger.warning("asset_inventory: seen_in_scans lookup failed for asset %s", asset.id)
        return []

    sessions = ScanSession.objects.filter(id__in=session_ids).order_by("-start_time")
    return [
        {
            "uuid": str(s.uuid),
            "status": s.status,
            "at": s.start_time.isoformat() if s.start_time else None,
        }
        for s in sessions
    ]


@router.get("/")
def list_assets(request, domain: str = "", kind: str = "", status: str = "",
                q: str = "", page: int = 1):
    qs = Asset.objects.select_related("domain").annotate(**_severity_counts())
    if domain:
        qs = qs.filter(domain__name__icontains=domain)
    if kind:
        qs = qs.filter(kind=kind)
    if status:
        qs = qs.filter(status=status)
    if q:
        qs = qs.filter(key__icontains=q)
    qs = qs.order_by("kind", "key")

    paginator = Paginator(qs, 25)
    p = paginator.get_page(page)
    return {
        "assets": [_row(a) for a in p],
        "total": paginator.count,
        "page": p.number,
        "total_pages": paginator.num_pages,
        "has_next": p.has_next(),
        "has_previous": p.has_previous(),
    }


@router.get("/summary/")
def assets_summary(request, domain: str = ""):
    qs = Asset.objects.all()
    if domain:
        qs = qs.filter(domain__name__icontains=domain)

    by_kind: dict[str, dict[str, int]] = {}
    for row in qs.values("kind", "status").annotate(n=Count("id")):
        by_kind.setdefault(row["kind"], {"active": 0, "gone": 0})[row["status"]] = row["n"]

    return {
        "total": qs.count(),
        "active": qs.filter(status="active").count(),
        "gone": qs.filter(status="gone").count(),
        "by_kind": by_kind,
    }


@router.get("/{asset_id}/")
def asset_detail(request, asset_id: int):
    a = get_object_or_404(Asset.objects.select_related("domain"), id=asset_id)
    findings = (
        a.findings.select_related("session")
        .order_by("-discovered_at")
    )
    return {
        "id": a.id,
        "kind": a.kind,
        "key": a.key,
        "domain": a.domain.name,
        "status": a.status,
        "first_seen": a.first_seen.isoformat(),
        "last_seen": a.last_seen.isoformat(),
        "extra": a.extra,
        "last_scan": str(a.last_scan.uuid) if a.last_scan_id else None,
        "findings": [_finding_brief(f) for f in findings],
        "seen_in_scans": _seen_in_scans(a),
    }
