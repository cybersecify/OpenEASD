"""Management command: run_scan — triggers a scan synchronously."""

from django.core.management.base import BaseCommand
from apps.core.scans.pipeline import create_scan_session, run_scan


class Command(BaseCommand):
    help = "Run a security scan for a domain"

    def add_arguments(self, parser):
        parser.add_argument("--domain", required=True, help="Target domain")

    def handle(self, *args, **options):
        domain = options["domain"]
        self.stdout.write(f"Starting scan for {domain}...")
        session = create_scan_session(domain, triggered_by="manual")
        if session is None:
            self.stdout.write(self.style.ERROR(f"Scan already active for {domain}"))
            return
        self.stdout.write(f"Session ID: {session.id} (UUID: {session.uuid})")
        run_scan(session.id)
        session.refresh_from_db()
        self.stdout.write(self.style.SUCCESS(
            f"Scan {session.status} — {session.total_findings} finding(s)"
        ))
