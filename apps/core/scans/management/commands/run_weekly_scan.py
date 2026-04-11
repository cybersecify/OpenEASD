"""Management command: run_weekly_scan."""

from django.core.management.base import BaseCommand
from apps.core.scans.pipeline import weekly_scan


class Command(BaseCommand):
    help = "Run weekly full scans for all configured domains"

    def handle(self, *args, **options):
        self.stdout.write("Running weekly full scans...")
        result = weekly_scan()
        self.stdout.write(self.style.SUCCESS(f"Done: {result}"))
