"""Huey task definitions for async scan execution."""

from huey.contrib.djhuey import task


@task()
def run_scan_task(session_id: int):
    """Execute a scan asynchronously via huey."""
    from .pipeline import run_scan

    run_scan(session_id)
