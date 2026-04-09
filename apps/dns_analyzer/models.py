from django.db import models

SEVERITY_CHOICES = [("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")]


class DNSFinding(models.Model):
    session = models.ForeignKey("scans.ScanSession", on_delete=models.CASCADE, related_name="dns_findings")
    domain = models.CharField(max_length=255)
    record_type = models.CharField(max_length=20, blank=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="low")
    title = models.CharField(max_length=500, blank=True)
    description = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-severity", "-discovered_at"]

    def __str__(self):
        return f"{self.severity.upper()}: {self.title} ({self.domain})"
