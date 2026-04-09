"""Management command: run_scan — triggers a scan synchronously."""

from django.core.management.base import BaseCommand
from apps.scans.models import ScanSession
from apps.scans.tasks import run_scan


class Command(BaseCommand):
    help = "Run a security scan for a domain"

    def add_arguments(self, parser):
        parser.add_argument("--domain", required=True, help="Target domain")
        parser.add_argument("--scan-type", default="full", choices=["full", "incremental"])

    def handle(self, *args, **options):
        domain = options["domain"]
        scan_type = options["scan_type"]

        self.stdout.write(f"Starting {scan_type} scan for {domain}...")
        session = ScanSession.objects.create(domain=domain, scan_type=scan_type)
        self.stdout.write(f"Session ID: {session.id}")

        # Run synchronously (no Celery broker needed for CLI)
        result = run_scan(session.id)
        self.stdout.write(self.style.SUCCESS(
            f"Scan complete: {result}"
        ))
