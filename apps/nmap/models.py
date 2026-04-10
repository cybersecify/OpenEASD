from django.db import models

RISK_CHOICES = [("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")]


class ServiceResult(models.Model):
    session = models.ForeignKey("scans.ScanSession", on_delete=models.CASCADE, related_name="services")
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
        return f"{self.host}:{self.port} ({self.service_name})"
