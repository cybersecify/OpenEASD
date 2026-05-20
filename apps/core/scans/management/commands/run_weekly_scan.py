"""Management command: run_weekly_scan."""

from django.core.management.base import BaseCommand
from apps.core.scheduler.scheduler import daily_scan


class Command(BaseCommand):
    help = "Run full scans for all configured domains"

    def handle(self, *args, **options):
        self.stdout.write("Running full scans for all active domains...")
        daily_scan()
        self.stdout.write(self.style.SUCCESS("Done"))
