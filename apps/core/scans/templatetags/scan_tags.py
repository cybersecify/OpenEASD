from django import template
from django.utils import timezone

register = template.Library()


@register.filter
def scan_duration_label(scan):
    """Return a human-readable duration string for the scan's When column.

    - running   -> "running Xm Ys"  (elapsed since start, at render time)
    - completed -> "took Xm Ys"
    - failed    -> "after Xm Ys"
    - others    -> "" (no sub-line shown)
    """
    if scan.status == "running":
        delta = timezone.now() - scan.start_time
        prefix = "running"
    elif scan.status in ("completed", "failed") and scan.end_time:
        delta = scan.end_time - scan.start_time
        prefix = "took" if scan.status == "completed" else "after"
    else:
        return ""

    total_seconds = max(0, int(delta.total_seconds()))
    minutes, seconds = divmod(total_seconds, 60)
    if minutes:
        return f"{prefix} {minutes}m {seconds:02d}s"
    return f"{prefix} {seconds}s"
