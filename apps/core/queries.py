"""Shared query helpers used across core sub-apps."""

from django.db.models import Max


def latest_session_ids(domains=None):
    """Return list of IDs of the latest completed session per domain.

    If *domains* is ``None``, returns for all domains.
    """
    from apps.core.scans.models import ScanSession

    qs = ScanSession.objects.filter(status="completed")
    if domains is not None:
        qs = qs.filter(domain__in=domains)
    rows = qs.values("domain").annotate(latest_id=Max("id"))
    return [r["latest_id"] for r in rows]
