"""
Insights models — pre-computed scan summaries.

ScanSummary    : one row per completed scan, stores severity counts + tool breakdown
FindingTypeSummary : global aggregate of the most recurring finding types across all scans
"""

from django.db import models


class ScanSummary(models.Model):
    session = models.OneToOneField(
        "scans.ScanSession", on_delete=models.CASCADE, related_name="summary"
    )
    domain = models.CharField(max_length=255, db_index=True)
    scan_date = models.DateTimeField(db_index=True)

    # Severity counts
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    total_findings = models.IntegerField(default=0)

    # Delta counts
    new_exposures = models.IntegerField(default=0)
    removed_exposures = models.IntegerField(default=0)

    # Per-tool breakdown: {"domain_security": 4, "nuclei": 12, ...}
    tool_breakdown = models.JSONField(default=dict)

    class Meta:
        ordering = ["-scan_date"]

    def __str__(self):
        return f"{self.domain} — {self.scan_date:%Y-%m-%d %H:%M}"


class FindingTypeSummary(models.Model):
    """Global aggregate — most recurring finding types across all scans."""
    title = models.CharField(max_length=500)
    check_type = models.CharField(max_length=50)
    severity = models.CharField(max_length=20)
    occurrence_count = models.IntegerField(default=0)
    last_seen = models.DateTimeField()

    class Meta:
        ordering = ["-occurrence_count"]
        unique_together = [("title", "check_type")]

    def __str__(self):
        return f"{self.title} ({self.check_type}) ×{self.occurrence_count}"
