"""Management command: run_daily_scan."""

from django.core.management.base import BaseCommand
from apps.core.scheduler.scheduler import daily_scan


class Command(BaseCommand):
    help = "Run daily incremental scans for all configured domains"

    def handle(self, *args, **options):
        self.stdout.write("Running daily incremental scans...")
        result = daily_scan()
        self.stdout.write(self.style.SUCCESS(f"Done: {result}"))
