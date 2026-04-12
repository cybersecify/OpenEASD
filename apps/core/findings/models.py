from django.db import models


SEVERITY_CHOICES = [
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
    ("info", "Info"),
]

SOURCE_CHOICES = [
    ("domain_security", "Domain Security"),
    ("nmap", "Nmap NSE"),
    ("tls_checker", "TLS Checker"),
    ("ssh_checker", "SSH Checker"),
    ("nuclei", "Nuclei"),
    ("web_checker", "Web Checker"),
]

STATUS_CHOICES = [
    ("open", "Open"),
    ("acknowledged", "Acknowledged"),
    ("in_progress", "In Progress"),
    ("resolved", "Resolved"),
    ("false_positive", "False Positive"),
]


class Finding(models.Model):
    """Unified finding model — replaces per-tool DomainFinding/NmapFinding.

    Tool-specific fields (cve, cvss_score, nse_script, service, etc.)
    live in the ``extra`` JSONField. Convenience @property accessors
    are exposed for backward compatibility with templates.
    """

    session = models.ForeignKey(
        "scans.ScanSession", on_delete=models.CASCADE, related_name="findings"
    )
    source = models.CharField(max_length=50, choices=SOURCE_CHOICES, db_index=True)
    check_type = models.CharField(max_length=50, blank=True, db_index=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, db_index=True)
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    remediation = models.TextField(blank=True)

    # Optional asset links — only one is typically set per finding
    subdomain = models.ForeignKey(
        "assets.Subdomain",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="findings",
    )
    ip_address = models.ForeignKey(
        "assets.IPAddress",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="findings",
    )
    port = models.ForeignKey(
        "assets.Port",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="findings",
    )
    url = models.ForeignKey(
        "assets.URL",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="findings",
    )

    # Where the finding applies (string for top-level apex findings)
    target = models.CharField(max_length=255, blank=True, db_index=True)

    # Tool-specific extras: cve, cvss_score, nse_script, template_id, etc.
    extra = models.JSONField(default=dict, blank=True)

    discovered_at = models.DateTimeField(auto_now_add=True)

    # Lifecycle tracking
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="open", db_index=True)
    assigned_to = models.CharField(max_length=150, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_note = models.TextField(blank=True)

    class Meta:
        ordering = ["-discovered_at"]
        indexes = [
            models.Index(fields=["session", "severity"]),
            models.Index(fields=["source", "severity"]),
        ]

    def __str__(self):
        return f"[{self.severity}] {self.title}"

    # ---------- backward-compatibility accessors ----------
    @property
    def cve(self) -> str:
        return self.extra.get("cve", "") if isinstance(self.extra, dict) else ""

    @property
    def cvss_score(self):
        return self.extra.get("cvss_score") if isinstance(self.extra, dict) else None

    @property
    def service(self) -> str:
        return self.extra.get("service", "") if isinstance(self.extra, dict) else ""

    @property
    def version(self) -> str:
        return self.extra.get("version", "") if isinstance(self.extra, dict) else ""

    @property
    def port_number(self):
        return self.extra.get("port_number") if isinstance(self.extra, dict) else None

    @property
    def address(self) -> str:
        if isinstance(self.extra, dict) and self.extra.get("address"):
            return self.extra["address"]
        if self.target and ":" in self.target:
            return self.target.rsplit(":", 1)[0]
        return self.target or ""

    @property
    def domain(self) -> str:
        """Backward-compat for DomainFinding.domain."""
        return self.target
