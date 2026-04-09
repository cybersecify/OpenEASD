"""Core models for OpenEASD configuration management."""

import json
import hashlib

from django.db import models


class ScanConfiguration(models.Model):
    """Stores scan configuration per domain."""

    domain = models.CharField(max_length=255)
    config_name = models.CharField(max_length=100)
    config_data = models.JSONField(default=dict)
    config_hash = models.CharField(max_length=64)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("domain", "config_name")]
        ordering = ["-updated_at"]

    def save(self, *args, **kwargs):
        self.config_hash = hashlib.sha256(
            json.dumps(self.config_data, sort_keys=True).encode()
        ).hexdigest()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.domain} - {self.config_name}"
