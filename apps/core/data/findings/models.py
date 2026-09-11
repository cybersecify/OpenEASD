from django.db import models


SEVERITY_CHOICES = [
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
    ("info", "Info"),
]

# SOURCE_CHOICES removed — auto-discovered from tool_meta.produces_findings via registry

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
    source = models.CharField(max_length=50, db_index=True)  # no choices constraint — registry is source of truth
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
        "web_assets.URL",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="findings",
    )
    # Persistent-inventory asset this finding applies to (apps/core/asset_inventory).
    # Nullable + best-effort: resolved by the inventory rollup at finalize; an
    # unresolvable target leaves it null and the finding behaves exactly as before.
    asset = models.ForeignKey(
        "asset_inventory.Asset",
        on_delete=models.SET_NULL,
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


def issue_key(source: str, check_type: str, title: str, target: str) -> str:
    """Stable cross-scan identity for a finding within a domain.

    Keyed on (source, check_type, title, target) — the same detection on the same
    host collapses to one persistent Issue across scans, while the same check on a
    *different* host is a distinct issue (per-asset triage). Extends the
    delta-detection key (source:check_type:title) with target for asset
    granularity. Uses \\x1f (unit separator) so colons in titles/targets can't
    collide two distinct issues into one.
    """
    return "\x1f".join((source or "", check_type or "", title or "", target or ""))


class Issue(models.Model):
    """Persistent, cross-scan identity for a finding — the *issue* that each
    per-scan Finding is an occurrence of.

    Populated by the fail-graceful rollup in ``rollup.py`` at scan finalize (never
    by tools directly), mirroring ``asset_inventory``. Its whole reason to exist is
    that ``status`` lives HERE, not on the per-scan ``Finding``: a triage decision
    (``false_positive`` / ``acknowledged`` / …) therefore persists across scans
    instead of resetting to ``open`` every run. Spec:
    docs/specs/2026-09-12-finding-centric-ui-direction.md (PR2).
    """

    domain = models.ForeignKey(
        "domains.Domain", on_delete=models.CASCADE, related_name="issues"
    )
    # Stable identity within the domain (see issue_key). Not user-facing.
    key = models.CharField(max_length=1024)

    # Denormalised display fields, refreshed from the latest occurrence.
    source = models.CharField(max_length=50, db_index=True)
    check_type = models.CharField(max_length=50, blank=True, db_index=True)
    title = models.CharField(max_length=500)
    target = models.CharField(max_length=255, blank=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, db_index=True)

    # PERSISTENT triage status — the point of this model.
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="open", db_index=True
    )

    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()

    # Latest occurrence + the persistent asset it sits on (grounding).
    last_finding = models.ForeignKey(
        "findings.Finding", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="+",
    )
    asset = models.ForeignKey(
        "asset_inventory.Asset", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="issues",
    )
    extra = models.JSONField(default=dict, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["domain", "key"], name="uniq_issue_per_domain"
            )
        ]
        indexes = [
            models.Index(fields=["domain", "status", "severity"]),
            models.Index(fields=["status", "severity"]),
        ]
        ordering = ["-last_seen"]

    def __str__(self):
        return f"{self.source}:{self.check_type}:{self.title[:40]} [{self.status}]"
