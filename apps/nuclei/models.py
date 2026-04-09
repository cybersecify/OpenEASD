from django.db import models

SEVERITY_CHOICES = [("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")]


class NucleiFinding(models.Model):
    session = models.ForeignKey("scans.ScanSession", on_delete=models.CASCADE, related_name="nuclei_findings")
    host = models.CharField(max_length=255, db_index=True)
    port = models.IntegerField(null=True, blank=True)
    template_id = models.CharField(max_length=200)
    template_name = models.CharField(max_length=500, blank=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, db_index=True)
    description = models.TextField(blank=True)
    matched_at = models.CharField(max_length=500, blank=True)
    cvss_score = models.FloatField(null=True, blank=True)
    cve_id = models.CharField(max_length=50, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    is_new = models.BooleanField(default=True)

    class Meta:
        ordering = ["-severity", "-discovered_at"]

    def __str__(self):
        return f"{self.severity.upper()}: {self.template_name or self.template_id} @ {self.host}"
