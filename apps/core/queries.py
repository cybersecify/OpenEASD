"""Shared query helpers used across core sub-apps."""

from django.db.models import Max


def latest_session_ids(domains=None):
    """Return list of IDs of the latest finished session per domain.

    "Finished" includes ``completed`` and ``partial`` — a partial scan still
    has real findings (steps that ran before the watchdog reap), so it should
    surface in dashboards and findings views.

    Subscans are excluded: they copy the parent's assets but run only a subset
    of tools and produce their own subset of findings. A subscan always has the
    highest id for its domain, so without this filter it would masquerade as the
    domain's "latest session" and collapse dashboards/findings/insights down to
    just the re-run tool's output until the next full scan.

    If *domains* is ``None``, returns for all domains.
    """
    from apps.core.scans.models import ScanSession

    qs = ScanSession.objects.filter(status__in=["completed", "partial"]).exclude(
        scan_type="subscan"
    )
    if domains is not None:
        qs = qs.filter(domain__in=domains)
    rows = qs.values("domain").annotate(latest_id=Max("id"))
    return [r["latest_id"] for r in rows]
