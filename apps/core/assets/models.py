from django.db import models


class Subdomain(models.Model):
    session = models.ForeignKey('scans.ScanSession', on_delete=models.CASCADE, related_name='asset_subdomains')
    domain = models.CharField(max_length=255)
    subdomain = models.CharField(max_length=255)
    source = models.CharField(max_length=50)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=['domain']), models.Index(fields=['subdomain'])]


class IPAddress(models.Model):
    session = models.ForeignKey('scans.ScanSession', on_delete=models.CASCADE, related_name='asset_ips')
    address = models.GenericIPAddressField()
    version = models.IntegerField()
    source = models.CharField(max_length=50)
    discovered_at = models.DateTimeField(auto_now_add=True)


class Port(models.Model):
    session = models.ForeignKey('scans.ScanSession', on_delete=models.CASCADE, related_name='asset_ports')
    port = models.IntegerField()
    protocol = models.CharField(max_length=10)
    state = models.CharField(max_length=20)
    service = models.CharField(max_length=100, blank=True)
    version = models.CharField(max_length=200, blank=True)
    source = models.CharField(max_length=50)
    discovered_at = models.DateTimeField(auto_now_add=True)


class URL(models.Model):
    session = models.ForeignKey('scans.ScanSession', on_delete=models.CASCADE, related_name='asset_urls')
    url = models.CharField(max_length=2048)
    status_code = models.IntegerField(null=True, blank=True)
    title = models.CharField(max_length=500, blank=True)
    source = models.CharField(max_length=50)
    discovered_at = models.DateTimeField(auto_now_add=True)


class Technology(models.Model):
    session = models.ForeignKey('scans.ScanSession', on_delete=models.CASCADE, related_name='asset_technologies')
    name = models.CharField(max_length=200)
    version = models.CharField(max_length=100, blank=True)
    category = models.CharField(max_length=100, blank=True)
    source = models.CharField(max_length=50)
    discovered_at = models.DateTimeField(auto_now_add=True)


class Certificate(models.Model):
    session = models.ForeignKey('scans.ScanSession', on_delete=models.CASCADE, related_name='asset_certificates')
    domain = models.CharField(max_length=255)
    issuer = models.CharField(max_length=500, blank=True)
    subject = models.CharField(max_length=500, blank=True)
    valid_from = models.DateTimeField(null=True, blank=True)
    valid_to = models.DateTimeField(null=True, blank=True)
    is_expired = models.BooleanField(default=False)
    source = models.CharField(max_length=50)
    discovered_at = models.DateTimeField(auto_now_add=True)
