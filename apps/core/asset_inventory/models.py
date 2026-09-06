"""Persistent, deduplicated asset inventory (spec: docs/specs/2026-09-06-asset-centric-inventory.md).

A scan's own Subdomain/IPAddress/Port/URL rows stay session-scoped (a per-scan
snapshot, unchanged). `Asset` is the derived layer on top: one row per unique
(domain, kind, key), carrying first_seen / last_seen / status across scans. It is
populated by the fail-graceful rollup in `rollup.py` at scan finalize — never by
the scanner tools directly.
"""

from django.db import models


class Asset(models.Model):
    KIND_CHOICES = [
        ("subdomain", "Subdomain"),
        ("ip", "IP Address"),
        ("port", "Port"),
        ("url", "URL"),
    ]
    STATUS_CHOICES = [
        ("active", "Active"),    # seen in the domain's latest covering scan
        ("gone", "Gone"),        # previously seen, absent from the latest covering scan
    ]

    # FK(Domain) so deleting a domain cascades its inventory (matches the
    # existing "delete a Domain wipes all its data" rule). The rollup resolves
    # session.domain (a string) to a Domain row and skips if none exists.
    domain = models.ForeignKey(
        "domains.Domain", on_delete=models.CASCADE, related_name="assets"
    )
    kind = models.CharField(max_length=20, choices=KIND_CHOICES, db_index=True)
    # Stable identity within (domain, kind): "api.example.com" | "1.2.3.4" |
    # "1.2.3.4:443/tcp" | "https://api.example.com/x". Normalised on write.
    key = models.CharField(max_length=2048)

    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    status = models.CharField(
        max_length=10, choices=STATUS_CHOICES, default="active", db_index=True
    )
    last_scan = models.ForeignKey(
        "scans.ScanSession", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="+",
    )
    # Tool-specific metadata: service, is_web, technologies, status_code, …
    extra = models.JSONField(default=dict, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["domain", "kind", "key"], name="uniq_asset_per_domain"
            )
        ]
        indexes = [
            models.Index(fields=["domain", "kind", "status"]),
            models.Index(fields=["kind", "status"]),
        ]
        ordering = ["kind", "key"]

    def __str__(self):
        return f"{self.kind}:{self.key}"
