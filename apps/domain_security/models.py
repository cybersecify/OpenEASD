from django.db import models

SEVERITY_CHOICES = [
    ("info", "Info"),
    ("low", "Low"),
    ("medium", "Medium"),
    ("high", "High"),
    ("critical", "Critical"),
]

CHECK_TYPE_CHOICES = [
    ("dns", "DNS"),
    ("ssl", "SSL/TLS"),
    ("email", "Email Security"),
    ("rdap", "RDAP/Domain"),
]


class DomainFinding(models.Model):
    """Unified finding model for all domain security checks."""

    session = models.ForeignKey(
        "scans.ScanSession",
        on_delete=models.CASCADE,
        related_name="domain_findings",
    )
    domain = models.CharField(max_length=255, db_index=True)
    check_type = models.CharField(max_length=20, choices=CHECK_TYPE_CHOICES, db_index=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, db_index=True)
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    extra = models.JSONField(default=dict, blank=True)  # expiry dates, lock status, record values, etc.
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-severity", "-discovered_at"]

    def __str__(self):
        return f"[{self.check_type.upper()}] {self.severity.upper()}: {self.title} ({self.domain})"
