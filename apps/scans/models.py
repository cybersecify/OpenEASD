"""
Django models for OpenEASD scan sessions.
"""

import uuid
from django.db import models


class ScanSession(models.Model):
    """Represents a single scan run against a domain."""

    SCAN_TYPE_CHOICES = [("full", "Full"), ("incremental", "Incremental")]
    STATUS_CHOICES = [
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    domain = models.CharField(max_length=255, db_index=True)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPE_CHOICES)
    workflow = models.ForeignKey(
        "workflow.Workflow", on_delete=models.SET_NULL, null=True, blank=True, related_name="sessions"
    )
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="running", db_index=True)
    config_hash = models.CharField(max_length=64, blank=True)
    total_findings = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-start_time"]

    def __str__(self):
        return f"[{self.id}] {self.domain} ({self.scan_type}) - {self.status}"


class ScanDelta(models.Model):
    """Records changes between consecutive scan sessions."""

    CHANGE_TYPE_CHOICES = [
        ("new", "New"),
        ("removed", "Removed"),
        ("modified", "Modified"),
    ]
    CHANGE_CATEGORY_CHOICES = [
        ("subdomain", "Subdomain"),
        ("service", "Service"),
        ("vulnerability", "Vulnerability"),
        ("port", "Port"),
        ("dns", "DNS"),
        ("ssl", "SSL"),
        ("email", "Email"),
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
