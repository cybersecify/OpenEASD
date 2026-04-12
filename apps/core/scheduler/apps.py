import logging
import os
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

        # Avoid double-start in Django's dev server (reloader spawns two processes).
        if os.environ.get("RUN_MAIN") != "true" and not os.environ.get("SERVER_SOFTWARE"):
            return

        from .scheduler import start_scheduler
        try:
            start_scheduler()
        except Exception as e:
            _logger.error(f"Scheduler failed to start: {e}", exc_info=True)
