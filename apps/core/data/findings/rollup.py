"""Roll a finished scan's findings into the persistent Issue register.

Called fail-graceful from ``_finalize_session`` (after the asset rollup, so
``Finding.asset`` links are already set). Gives each finding a cross-scan
identity so triage status persists: a dismissed false positive stays dismissed on
the next scan instead of resetting to ``open``. Mirrors
``apps/core/data/asset_inventory/rollup.py``.

Idempotent (F1): re-running finalize (e.g. a DBOS step replay) converges — every
write is an upsert with no running counters, so a replay produces the same state.

Spec: docs/specs/2026-09-12-finding-centric-ui-direction.md (PR2).
"""

import logging

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)


def rollup_session_issues(session) -> None:
    """Upsert one Issue per finding-identity key for this scan, carrying the
    persistent triage status forward."""
    from apps.core.data.domains.models import Domain

    from .models import Issue, issue_key

    if session.scan_type == "subscan":
        # Subscans re-run a subset of tools; full scans define the issue set.
        return

    domain = Domain.objects.filter(name=session.domain).first()
    if domain is None:
        logger.info(
            "[issues:%s] no Domain row for %s — skipping issue rollup",
            session.id, session.domain,
        )
        return

    now = timezone.now()
    keys_seen: set[str] = set()

    with transaction.atomic():
        # Exclude the scan_coverage meta-warning — it's a finalize-generated
        # marker, not a real attack-surface issue (same rule as delta/count).
        for f in session.findings.select_related("asset").exclude(source="scan_coverage"):
            k = issue_key(f.source, f.check_type, f.title, f.target)
            keys_seen.add(k)
            issue, created = Issue.objects.get_or_create(
                domain=domain, key=k,
                defaults={
                    "source": f.source, "check_type": f.check_type,
                    "title": f.title, "target": f.target, "severity": f.severity,
                    "status": "open", "first_seen": now, "last_seen": now,
                    "last_finding": f, "asset": f.asset,
                },
            )
            if not created:
                issue.last_seen = now
                issue.severity = f.severity          # reflect the latest occurrence
                issue.last_finding = f
                if f.asset_id:
                    issue.asset = f.asset
                # Persist triage across scans; only re-open a *resolved* issue that
                # has reappeared (regression). false_positive / acknowledged /
                # in_progress are deliberate decisions and must survive a re-scan.
                if issue.status == "resolved":
                    issue.status = "open"
                issue.save(update_fields=[
                    "last_seen", "severity", "last_finding", "asset", "status",
                ])

    logger.info(
        "[issues:%s] rolled up %d issue key(s) for %s",
        session.id, len(keys_seen), domain.name,
    )
