import logging
import sys
from django.apps import AppConfig

_logger = logging.getLogger(__name__)


class SchedulerConfig(AppConfig):
    name = "apps.core.scheduler"
    label = "scheduler"

    def ready(self):
        from django.conf import settings

        if not getattr(settings, "SCHEDULER_ENABLED", True):
            _logger.info("Scheduler disabled via SCHEDULER_ENABLED=False")
            return

        # Scheduler runs in the qcluster (task worker) process ONLY. The previous
        # RUN_MAIN-based guard only worked for Django's dev server — under gunicorn,
        # SERVER_SOFTWARE is set in every worker, so the scheduler started N times
        # (once per worker) and N copies of every job fired. Anchoring on `qcluster`
        # in sys.argv gives one scheduler per deployment:
        #   - Docker single-container: scheduler in qcluster, none in gunicorn workers
        #   - K8s split:                scheduler in worker pod, none in web pod
        #   - Local dev (manage.py qcluster): scheduler runs
        #   - Local dev (manage.py runserver alone, no worker): scheduler does NOT run
        #     — start a separate `manage.py qcluster` in another terminal if needed.
        if not any("qcluster" in arg for arg in sys.argv):
            return

        from .scheduler import setup_core_schedules
        try:
            setup_core_schedules()
        except Exception as e:
            _logger.error(f"Scheduler setup failed: {e}", exc_info=True)
