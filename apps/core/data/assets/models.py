from django.db import models


class Subdomain(models.Model):
    session = models.ForeignKey('scans.ScanSession', on_delete=models.CASCADE, related_name='subdomains')
    domain = models.CharField(max_length=255)
    subdomain = models.CharField(max_length=255)
    source = models.CharField(max_length=50)
    is_active = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("session", "subdomain")]
        indexes = [
            models.Index(fields=['domain']),
            models.Index(fields=['subdomain']),
            models.Index(fields=['is_active']),
        ]
        ordering = ["subdomain"]

    def __str__(self):
        return self.subdomain


class IPAddress(models.Model):
    session = models.ForeignKey('scans.ScanSession', on_delete=models.CASCADE, related_name='asset_ips')
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name='ips', null=True, blank=True)
    address = models.GenericIPAddressField()
    version = models.IntegerField()
    source = models.CharField(max_length=50)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=['address'])]


class Port(models.Model):
    session = models.ForeignKey('scans.ScanSession', on_delete=models.CASCADE, related_name='ports')
    ip_address = models.ForeignKey(IPAddress, on_delete=models.CASCADE, related_name='ports', null=True, blank=True)
    address = models.CharField(max_length=64, default='', blank=True)  # plain string for display when ip_address FK is null
    port = models.IntegerField()
    protocol = models.CharField(max_length=10, default='tcp')
    state = models.CharField(max_length=20, default='open')
    service = models.CharField(max_length=100, blank=True)
    version = models.CharField(max_length=200, blank=True)
    is_web = models.BooleanField(default=False)
    source = models.CharField(max_length=50)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("session", "address", "port", "protocol")]
        indexes = [models.Index(fields=['address']), models.Index(fields=['port'])]
        ordering = ["address", "port"]

    def __str__(self):
        return f"{self.address}:{self.port}/{self.protocol}"
