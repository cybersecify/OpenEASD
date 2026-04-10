import logging
import os
from django.apps import AppConfig

_logger = logging.getLogger(__name__)


class DashboardConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core.dashboard"
    label = "core"

    def ready(self):
        from django.conf import settings

        # Opt-out: set SCHEDULER_ENABLED=False on extra gunicorn workers so only
        # one process runs the scheduler and jobs don't fire multiple times.
        if not getattr(settings, "SCHEDULER_ENABLED", True):
            _logger.info("Scheduler disabled via SCHEDULER_ENABLED=False")
            return

        # Avoid double-start in Django's dev server (reloader spawns two processes).
        # RUN_MAIN is set to 'true' only in the child (app) process, not the reloader.
        if os.environ.get("RUN_MAIN") != "true" and not os.environ.get("SERVER_SOFTWARE"):
            return

        from apps.core.scheduler import start_scheduler
        try:
            start_scheduler()
        except Exception as e:
            _logger.error(f"Scheduler failed to start: {e}", exc_info=True)
