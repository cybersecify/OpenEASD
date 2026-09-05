"""DBOS worker — executes durable scan/AI workflows. Replaces `manage.py qcluster`.

Launches the DBOS engine (which connects to the system database, recovers any
workflows interrupted by a previous crash, and starts draining the `scans`
queue), then blocks until the process is signalled.
"""

import signal
import threading

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Run the DBOS durable-execution worker (scan + AI workflows)."

    def handle(self, *args, **options):
        from dbos import DBOS

        from apps.core.durable.dbos_app import configure_dbos

        configure_dbos()
        DBOS.launch()
        self.stdout.write(self.style.SUCCESS("DBOS worker launched — draining the scans queue. Ctrl-C to stop."))

        stop = threading.Event()
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        try:
            stop.wait()
        finally:
            DBOS.destroy()
            self.stdout.write("DBOS worker stopped.")
