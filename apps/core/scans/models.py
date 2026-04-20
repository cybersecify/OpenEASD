"""
Django models for OpenEASD scan sessions.
"""

import uuid
from django.db import models


class ScanSession(models.Model):
    """Represents a single scan run against a domain."""

    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("cancelled", "Cancelled"),
        ("failed", "Failed"),
    ]
    TRIGGERED_BY_CHOICES = [
        ("manual", "Manual"),
        ("scheduled", "Scheduled"),
        ("recurring", "Recurring"),
    ]

    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    domain = models.CharField(max_length=255, db_index=True)
    scan_type = models.CharField(max_length=20, default="full")
    triggered_by = models.CharField(max_length=20, choices=TRIGGERED_BY_CHOICES, default="manual")
    workflow = models.ForeignKey(
        "workflow.Workflow", on_delete=models.SET_NULL, null=True, blank=True, related_name="sessions"
    )
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending", db_index=True)
    total_findings = models.IntegerField(default=0)

    class Meta:
        ordering = ["-start_time"]

    def __str__(self):
        return f"[{self.id}] {self.domain} ({self.scan_type}) - {self.status}"


class ScanDelta(models.Model):
    """Records changes between consecutive scan sessions."""

    CHANGE_TYPE_CHOICES = [
        ("new", "New"),
        ("removed", "Removed"),
    ]
    CHANGE_CATEGORY_CHOICES = [
        ("finding", "Finding"),
        ("domain_finding", "Domain Finding"),
    ]

    session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name="deltas")
    previous_session = models.ForeignKey(
        ScanSession, on_delete=models.SET_NULL, null=True, blank=True, related_name="next_deltas"
    )
    change_type = models.CharField(max_length=20, choices=CHANGE_TYPE_CHOICES)
    change_category = models.CharField(max_length=20, choices=CHANGE_CATEGORY_CHOICES)
    item_identifier = models.CharField(max_length=500)
    change_details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.change_type} {self.change_category}: {self.item_identifier}"
