"""
Django models for OpenEASD scan data.

Replaces the raw SQLite schema in the original src/core/database.py
using the Django ORM.
"""

from django.db import models


class ScanSession(models.Model):
    """Represents a single scan run against a domain."""

    SCAN_TYPE_CHOICES = [("full", "Full"), ("incremental", "Incremental")]
    STATUS_CHOICES = [
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    domain = models.CharField(max_length=255, db_index=True)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPE_CHOICES)
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


class Subdomain(models.Model):
    """Subdomain discovered during a scan session."""

    session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name="subdomains")
    subdomain = models.CharField(max_length=255, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = [("session", "subdomain")]
        ordering = ["subdomain"]

    def __str__(self):
        return self.subdomain


class Service(models.Model):
    """Network service discovered on a host."""

    RISK_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name="services")
    host = models.CharField(max_length=255)
    port = models.IntegerField()
    service_name = models.CharField(max_length=100, blank=True)
    version = models.CharField(max_length=200, blank=True)
    protocol = models.CharField(max_length=10, default="tcp")
    state = models.CharField(max_length=20, default="open")
    risk_level = models.CharField(max_length=20, choices=RISK_CHOICES, default="low")
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("session", "host", "port", "protocol")]
        ordering = ["host", "port"]

    def __str__(self):
        return f"{self.host}:{self.port}/{self.protocol} ({self.service_name})"


class Vulnerability(models.Model):
    """Security vulnerability discovered during a scan."""

    SEVERITY_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]
    CONFIDENCE_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
    ]

    session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name="vulnerabilities")
    host = models.CharField(max_length=255, db_index=True)
    port = models.IntegerField(null=True, blank=True)
    vulnerability_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, db_index=True)
    title = models.CharField(max_length=500, blank=True)
    description = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    cvss_score = models.FloatField(null=True, blank=True)
    cve_id = models.CharField(max_length=50, blank=True)
    mitre_technique = models.CharField(max_length=100, blank=True)
    confidence = models.CharField(max_length=20, choices=CONFIDENCE_CHOICES, default="medium")
    discovered_at = models.DateTimeField(auto_now_add=True)
    is_new = models.BooleanField(default=True)

    class Meta:
        ordering = ["-severity", "-discovered_at"]

    def __str__(self):
        return f"{self.severity.upper()}: {self.title or self.vulnerability_type} @ {self.host}"


class Alert(models.Model):
    """Alert notification sent for a vulnerability."""

    ALERT_TYPE_CHOICES = [
        ("slack", "Slack"),
        ("email", "Email"),
        ("webhook", "Webhook"),
    ]
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("sent", "Sent"),
        ("failed", "Failed"),
    ]

    vulnerability = models.ForeignKey(
        Vulnerability, on_delete=models.CASCADE, related_name="alerts", null=True, blank=True
    )
    session = models.ForeignKey(
        ScanSession, on_delete=models.CASCADE, related_name="alerts", null=True, blank=True
    )
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPE_CHOICES)
    severity_threshold = models.CharField(max_length=20)
    message = models.TextField(blank=True)
    sent_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending", db_index=True)
    retry_count = models.IntegerField(default=0)
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ["-sent_at"]

    def __str__(self):
        return f"{self.alert_type} alert [{self.status}] - {self.sent_at}"


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
