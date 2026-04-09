import os
from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core"
    label = "core"

    def ready(self):
        # Avoid double-start in Django's dev server (reloader spawns two processes).
        # RUN_MAIN is set to 'true' only in the child (app) process, not the reloader.
        if os.environ.get("RUN_MAIN") != "true" and not os.environ.get("SERVER_SOFTWARE"):
            return

        from .scheduler import start_scheduler
        try:
            start_scheduler()
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Scheduler failed to start: {e}")
