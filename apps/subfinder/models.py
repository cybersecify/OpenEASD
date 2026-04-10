from django.db import models


class Subdomain(models.Model):
    session = models.ForeignKey("scans.ScanSession", on_delete=models.CASCADE, related_name="subdomains")
    subdomain = models.CharField(max_length=255, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = [("session", "subdomain")]
        ordering = ["subdomain"]

    def __str__(self):
        return self.subdomain
