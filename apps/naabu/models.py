"""NaabuConfig — singleton model for naabu scan settings, editable via Django admin."""

from django.db import models


class NaabuConfig(models.Model):
    TOP_PORTS_CHOICES = [
        ("100",  "Top 100"),
        ("1000", "Top 1000"),
        ("full", "All 65535"),
        ("custom", "Custom (see Custom Ports field)"),
    ]

    top_ports = models.CharField(
        max_length=10,
        choices=TOP_PORTS_CHOICES,
        default="100",
        help_text="Number of top ports to scan. Ignored when Custom Ports is set.",
    )
    custom_ports = models.CharField(
        max_length=500,
        blank=True,
        default="",
        help_text="Custom port list/range, e.g. 22,80,443,8080-8090. Overrides Top Ports when set.",
    )
    rate = models.PositiveIntegerField(
        default=1000,
        help_text="Packets per second. Lower values are stealthier but slower.",
    )
    scan_timeout = models.PositiveIntegerField(
        default=900,
        help_text="Maximum scan duration in seconds before naabu is killed.",
    )
    exclude_ports = models.CharField(
        max_length=500,
        blank=True,
        default="",
        help_text="Ports to exclude, e.g. 9200,27017. Leave blank to exclude nothing.",
    )

    class Meta:
        verbose_name = "Naabu Configuration"
        verbose_name_plural = "Naabu Configuration"

    def __str__(self):
        if self.custom_ports:
            return f"Naabu Config (custom: {self.custom_ports})"
        return f"Naabu Config (top {self.top_ports})"

    @classmethod
    def get(cls):
        """Return the singleton config, creating defaults if none exists."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj
