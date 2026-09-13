"""Issue register — the persistent, cross-scan projection of Findings.

Split out of the ``findings`` app (D-017: Issue is a first-class entity — the
persistent finding layer — paralleling ``asset_inventory`` for assets). The model
KEEPS its original table (``findings_issue``, via ``Meta.db_table``) so the split
is a state-only move with no data migration. Populated by ``rollup.py`` at scan
finalize (never by tools). ``status`` lives here (not on per-scan ``Finding``) so
triage persists across scans.
"""

from django.db import models

# Choice sets stay canonical in the findings app (Finding + Issue share them).
from apps.core.data.findings.models import SEVERITY_CHOICES, STATUS_CHOICES


def issue_key(source: str, check_type: str, title: str, target: str) -> str:
    """Stable cross-scan identity for a finding within a domain.

    Keyed on (source, check_type, title, target) — the same detection on the same
    host collapses to one persistent Issue across scans, while the same check on a
    *different* host is a distinct issue (per-asset triage). Uses \\x1f (unit
    separator) so colons in titles/targets can't collide two distinct issues.
    """
    return "\x1f".join((source or "", check_type or "", title or "", target or ""))


class Issue(models.Model):
    """Persistent, cross-scan identity for a finding — the *issue* that each
    per-scan Finding is an occurrence of. Triage ``status`` persists here."""

    domain = models.ForeignKey(
        "domains.Domain", on_delete=models.CASCADE, related_name="issues"
    )
    key = models.CharField(max_length=1024)

    source = models.CharField(max_length=50, db_index=True)
    check_type = models.CharField(max_length=50, blank=True, db_index=True)
    title = models.CharField(max_length=500)
    target = models.CharField(max_length=255, blank=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, db_index=True)

    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="open", db_index=True
    )

    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()

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
        db_table = "findings_issue"  # keep the original table — state-only move
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
