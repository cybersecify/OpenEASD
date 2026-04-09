from django.db import models

SEVERITY_CHOICES = [("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")]


class SSLFinding(models.Model):
    session = models.ForeignKey("scans.ScanSession", on_delete=models.CASCADE, related_name="ssl_findings")
    domain = models.CharField(max_length=255)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="low")
    issue_type = models.CharField(max_length=100, blank=True)
    title = models.CharField(max_length=500, blank=True)
    description = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    expiry_date = models.DateTimeField(null=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-severity", "-discovered_at"]

    def __str__(self):
        return f"{self.severity.upper()}: {self.title} ({self.domain})"
