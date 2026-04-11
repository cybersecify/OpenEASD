from django.db import models


SEVERITY_CHOICES = [
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
    ("info", "Info"),
]


class NmapFinding(models.Model):
    session = models.ForeignKey("scans.ScanSession", on_delete=models.CASCADE, related_name="nmap_findings")
    port = models.ForeignKey("assets.Port", on_delete=models.CASCADE, related_name="nmap_findings", null=True, blank=True)
    address = models.CharField(max_length=64, db_index=True)
    port_number = models.IntegerField()
    service = models.CharField(max_length=100, blank=True)
    version = models.CharField(max_length=200, blank=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="info", db_index=True)
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    nse_script = models.CharField(max_length=100, default="vulners")
    cve = models.CharField(max_length=30, blank=True, db_index=True)
    cvss_score = models.FloatField(null=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-cvss_score", "-discovered_at"]
        indexes = [models.Index(fields=["address", "port_number"])]

    def __str__(self):
        return f"{self.title} on {self.address}:{self.port_number}"
