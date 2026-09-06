"""Roll a finished scan's session-scoped assets into the persistent inventory.

Called (fail-graceful) from `_finalize_session` after `build_insights`. Idempotent
— re-running finalize (e.g. DBOS step replay) converges to the same state.

Honest `gone`-marking (spec principle 4): a kind is only gone-marked when the
scan **completed** and actually **observed ≥1 asset of that kind** — a kind that
produced nothing this scan is left alone (can't tell "not run" from "found
nothing"), and partial/failed scans and subscans never gone-mark.
"""

import logging

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)


def _observed(session) -> dict[str, dict[str, dict]]:
    """Return {kind: {key: extra}} for every asset this session produced."""
    out: dict[str, dict[str, dict]] = {"subdomain": {}, "ip": {}, "port": {}, "url": {}}

    for sub in session.subdomains.all():
        out["subdomain"][sub.subdomain] = {"source": sub.source, "is_active": sub.is_active}

    for ip in session.asset_ips.all():
        out["ip"][ip.address] = {"version": ip.version, "source": ip.source}

    for port in session.ports.all():
        key = f"{port.address}:{port.port}/{port.protocol}"
        out["port"][key] = {
            "service": port.service, "is_web": port.is_web,
            "state": port.state, "version": port.version,
        }

    for url in session.urls.all():
        out["url"][url.url] = {
            "status_code": url.status_code, "web_server": url.web_server,
            "technologies": url.technologies, "reachability": url.reachability,
        }

    return out


def _link_findings(session, domain) -> None:
    """Best-effort: point each of this scan's findings at its inventory Asset."""
    from apps.core.findings.models import Finding

    from .models import Asset

    # Build a key→Asset map once for this domain (small: one domain's inventory).
    assets = {(a.kind, a.key): a for a in Asset.objects.filter(domain=domain)}

    to_update = []
    for f in session.findings.select_related("port", "url").all():
        asset = None
        if f.url_id and f.url:
            asset = assets.get(("url", f.url.url))
        if asset is None and f.port_id and f.port:
            key = f"{f.port.address}:{f.port.port}/{f.port.protocol}"
            asset = assets.get(("port", key))
        if asset is None and f.target:
            # target is a hostname or "ip:port" — try subdomain then ip.
            asset = assets.get(("subdomain", f.target)) or assets.get(("ip", f.target))
        if asset is not None and f.asset_id != asset.id:
            f.asset = asset
            to_update.append(f)

    if to_update:
        Finding.objects.bulk_update(to_update, ["asset"])


def rollup_session(session) -> None:
    """Upsert this scan's assets into the inventory + honest gone-marking."""
    from apps.core.domains.models import Domain

    from .models import Asset

    if session.scan_type == "subscan":
        return  # subscans refine findings, they don't redefine the surface

    domain = Domain.objects.filter(name=session.domain).first()
    if domain is None:
        logger.info(
            "[asset_inventory:%s] no Domain row for %s — skipping rollup",
            session.id, session.domain,
        )
        return

    now = timezone.now()
    observed = _observed(session)

    with transaction.atomic():
        for kind, items in observed.items():
            for key, extra in items.items():
                asset, created = Asset.objects.get_or_create(
                    domain=domain, kind=kind, key=key,
                    defaults={
                        "first_seen": now, "last_seen": now, "status": "active",
                        "last_scan": session, "extra": extra,
                    },
                )
                if not created:
                    asset.last_seen = now
                    asset.status = "active"
                    asset.last_scan = session
                    asset.extra = {**(asset.extra or {}), **extra}
                    asset.save(update_fields=["last_seen", "status", "last_scan", "extra"])

        if session.status == "completed":
            for kind, items in observed.items():
                if not items:
                    continue  # kind not covered / found nothing → don't gone-mark
                (Asset.objects
                 .filter(domain=domain, kind=kind, status="active")
                 .exclude(key__in=items.keys())
                 .update(status="gone"))

    _link_findings(session, domain)
    logger.info("[asset_inventory:%s] rolled up assets for %s", session.id, domain.name)
