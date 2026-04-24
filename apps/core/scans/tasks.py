"""Django-Q2 task definitions for async scan execution."""

from django_q.tasks import async_task


def run_scan_task(session_id: int):
    """Enqueue a scan to run asynchronously via Django-Q2."""
    async_task("apps.core.scans.tasks._run_scan", session_id)


def _run_scan(session_id: int):
    """Worker entry point — called by Django-Q2 cluster."""
    from .pipeline import run_scan

    run_scan(session_id)
