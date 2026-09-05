"""Scan enqueue — DBOS durable execution (replaces Django-Q2).

The API/scheduler still just call run_scan_task(session_id); it now durably
enqueues a DBOS scan workflow instead of a Django-Q task. The workflow
(apps/core/durable/workflows.py) resumes across worker restarts, so there is
no separate `_run_scan` worker entry point and no stuck-scan reaping.
"""


def run_scan_task(session_id: int) -> None:
    """Durably enqueue a scan. Deduplicated by session id (a double-submit
    returns the existing run rather than starting a second)."""
    from apps.core.durable.workflows import enqueue_scan

    enqueue_scan(session_id)
