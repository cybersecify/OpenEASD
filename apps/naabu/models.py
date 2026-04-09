from django.db import models


class PortResult(models.Model):
    session = models.ForeignKey("scans.ScanSession", on_delete=models.CASCADE, related_name="port_results")
    host = models.CharField(max_length=255)
    port = models.IntegerField()
    protocol = models.CharField(max_length=10, default="tcp")
    state = models.CharField(max_length=20, default="open")
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("session", "host", "port", "protocol")]
        ordering = ["host", "port"]

    def __str__(self):
        return f"{self.host}:{self.port}/{self.protocol}"
