"""Prometheus-format metrics exporter (H2 — queue/consumer observability).

Design note: rather than in-process prometheus_client counters (which would need
the worker to run its own HTTP listener AND cross-pod aggregation between the web
and worker processes), this is a **DB-backed exporter**. `render_metrics()` queries
the shared Postgres on each scrape and emits the Prometheus text exposition format.
That makes the numbers drift-free (they reflect the real stored state), survive
process restarts, and require no new dependency or worker listener — the web tier's
`GET /metrics` serves them for both tiers. The trade-off vs. true counters: these
are point-in-time gauges (plus journey-latency derived from stored timestamps), so
there are no per-request histograms; for this system's scale that is sufficient and
is what the hardening plan's principle #13 ("measure the whole journey") needs.
"""

from django.db.models import Count
from django.utils import timezone

_TERMINAL = ("completed", "failed", "partial", "cancelled")
_ACTIVE = ("pending", "running")


def _line(name, value, labels=None):
    if labels:
        label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
        return f"{name}{{{label_str}}} {value}"
    return f"{name} {value}"


def render_metrics() -> str:
    """Return the Prometheus text exposition for the current DB state."""
    from apps.core.data.findings.models import Finding
    from apps.core.engine.scans.models import ScanSession

    out = []

    def block(name, help_text, mtype, samples):
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} {mtype}")
        out.extend(samples)

    # --- scans by status ---
    status_counts = {
        row["status"]: row["n"]
        for row in ScanSession.objects.values("status").annotate(n=Count("id"))
    }
    block(
        "openeasd_scans", "Scan sessions by status.", "gauge",
        [_line("openeasd_scans", status_counts.get(s, 0), {"status": s})
         for s in ("pending", "running", *[t for t in _TERMINAL])],
    )

    # --- queue depth (active scans waiting or running) ---
    queue_depth = ScanSession.objects.filter(status__in=_ACTIVE).count()
    block("openeasd_scan_queue_depth", "Scans pending or running.", "gauge",
          [_line("openeasd_scan_queue_depth", queue_depth)])

    # --- findings by severity ---
    sev_counts = {
        row["severity"]: row["n"]
        for row in Finding.objects.values("severity").annotate(n=Count("id"))
    }
    block(
        "openeasd_findings", "Findings by severity.", "gauge",
        [_line("openeasd_findings", sev_counts.get(s, 0), {"severity": s})
         for s in ("critical", "high", "medium", "low", "info")],
    )

    # --- domains tracked ---
    domain_count = (
        ScanSession.objects.order_by().values_list("domain", flat=True).distinct().count()
    )
    block("openeasd_domains", "Distinct domains with scan history.", "gauge",
          [_line("openeasd_domains", domain_count)])

    # --- journey latency: enqueue (start_time) -> finalize (end_time) ---
    # principle #13: measure the whole journey, not each phase. We emit the most
    # recent completed scan's journey and how many completed scans we've recorded.
    latest_done = (
        ScanSession.objects.filter(status__in=_TERMINAL, end_time__isnull=False)
        .order_by("-end_time")
        .values("start_time", "end_time")
        .first()
    )
    if latest_done:
        journey = (latest_done["end_time"] - latest_done["start_time"]).total_seconds()
        block("openeasd_scan_last_journey_seconds",
              "Enqueue->finalize seconds for the most recent finished scan.", "gauge",
              [_line("openeasd_scan_last_journey_seconds", round(journey, 3))])

    # --- staleness of the worker: seconds since the most recent heartbeat ---
    # A growing value while queue_depth>0 means the worker has stopped progressing.
    latest_beat = (
        ScanSession.objects.filter(last_progress_at__isnull=False)
        .order_by("-last_progress_at")
        .values_list("last_progress_at", flat=True)
        .first()
    )
    if latest_beat:
        age = (timezone.now() - latest_beat).total_seconds()
        block("openeasd_seconds_since_last_progress",
              "Seconds since any scan step last completed (worker liveness).", "gauge",
              [_line("openeasd_seconds_since_last_progress", round(age, 1))])

    return "\n".join(out) + "\n"
