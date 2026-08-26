from django.db import models


class URL(models.Model):
    session = models.ForeignKey('scans.ScanSession', on_delete=models.CASCADE, related_name='urls')
    port = models.ForeignKey('assets.Port', on_delete=models.CASCADE, related_name='urls', null=True, blank=True)
    subdomain = models.ForeignKey('assets.Subdomain', on_delete=models.CASCADE, related_name='urls', null=True, blank=True)
    url = models.CharField(max_length=2048)
    scheme = models.CharField(max_length=10, blank=True)
    host = models.CharField(max_length=255, blank=True)
    port_number = models.IntegerField(null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    title = models.CharField(max_length=500, blank=True)
    web_server = models.CharField(max_length=200, blank=True)
    content_length = models.IntegerField(null=True, blank=True)
    # WAF/edge reachability at probe time (httpx). Blank for non-httpx sources.
    # reached | blocked | challenged | rate_limited — see apps/httpx/waf.py.
    reachability = models.CharField(max_length=20, blank=True)
    # Technology fingerprint from httpx -tech-detect (wappalyzer-style): a plain
    # list of technology name strings, e.g. ["Nginx", "PHP", "WordPress"].
    # Empty for non-httpx sources. Versions/EOL inference is out of scope here.
    technologies = models.JSONField(default=list, blank=True)
    source = models.CharField(max_length=50)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "assets_url"  # reuse existing table from assets app
        unique_together = [("session", "url")]
        indexes = [models.Index(fields=['host']), models.Index(fields=['status_code'])]
        ordering = ["url"]

    def __str__(self):
        return self.url
