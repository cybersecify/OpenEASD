"""
Django-adapted scan orchestrator.

In the original project this used Prefect flows. Now it delegates to
Celery tasks defined in apps/scans/tasks.py.
This module is kept as a thin compatibility shim for any code that
imports SecurityScanOrchestrator directly.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class SecurityScanOrchestrator:
    """
    Thin orchestration wrapper.

    The heavy lifting has moved to Celery tasks (apps/scans/tasks.py).
    This class provides a synchronous interface for management commands
    or one-off script usage.
    """

    def __init__(self, config_manager=None):
        self.config_manager = config_manager

    def start_scan(self, domain: str, scan_type: str = "full") -> dict:
        """Create a scan session and enqueue the Celery task."""
        import django
        django.setup()

        from apps.scans.models import ScanSession
        from apps.scans.tasks import run_scan

        session = ScanSession.objects.create(domain=domain, scan_type=scan_type)
        task = run_scan.delay(session.id)
        logger.info(f"Scan enqueued: session={session.id} task={task.id}")
        return {"session_id": session.id, "task_id": task.id}

    def get_scan_status(self, session_id: int) -> Optional[dict]:
        """Return current status of a scan session."""
        from apps.scans.models import ScanSession

        try:
            session = ScanSession.objects.get(id=session_id)
            return {
                "session_id": session.id,
                "domain": session.domain,
                "scan_type": session.scan_type,
                "status": session.status,
                "total_findings": session.total_findings,
                "start_time": str(session.start_time),
                "end_time": str(session.end_time) if session.end_time else None,
            }
        except ScanSession.DoesNotExist:
            return None

    def get_scan_results(self, session_id: int) -> Optional[dict]:
        """Return full results of a completed scan."""
        from apps.scans.models import ScanSession
        from apps.scans.serializers import ScanSessionDetailSerializer

        try:
            session = ScanSession.objects.get(id=session_id)
            return ScanSessionDetailSerializer(session).data
        except ScanSession.DoesNotExist:
            return None
