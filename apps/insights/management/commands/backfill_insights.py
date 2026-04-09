"""
Management command to backfill ScanSummary for existing completed scans.

Usage:
    uv run manage.py backfill_insights
"""

from django.core.management.base import BaseCommand

from apps.scans.models import ScanSession
from apps.insights.builder import build_insights
from apps.insights.models import ScanSummary


class Command(BaseCommand):
    help = "Backfill insight summaries for all completed scans that lack one."

    def handle(self, *args, **options):
        existing_ids = ScanSummary.objects.values_list("session_id", flat=True)
        scans = ScanSession.objects.filter(status="completed").exclude(id__in=existing_ids)
        total = scans.count()

        if total == 0:
            self.stdout.write(self.style.SUCCESS("All completed scans already have summaries."))
            return

        self.stdout.write(f"Backfilling {total} scan(s)...")
        for scan in scans:
            build_insights(scan)
            self.stdout.write(f"  ✓ session {scan.id} — {scan.domain}")

        self.stdout.write(self.style.SUCCESS(f"Done. {total} summary(s) created."))
