from django.db import models


class NotificationConfig(models.Model):
    """Singleton (pk=1) — stores webhook URLs and alert threshold in the DB."""
    THRESHOLD_CHOICES = [
        ("critical", "Critical only"),
        ("high",     "High and above"),
        ("medium",   "Medium and above"),
        ("low",      "Low and above"),
    ]

    slack_webhook_url  = models.TextField(blank=True, default="")
    teams_webhook_url  = models.TextField(blank=True, default="")
    severity_threshold = models.CharField(max_length=20, choices=THRESHOLD_CHOICES, default="high")

    class Meta:
        verbose_name = "Notification config"

    @classmethod
    def get(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def __str__(self):
        return f"NotificationConfig (threshold={self.severity_threshold})"


class Alert(models.Model):
    ALERT_TYPE_CHOICES = [("slack", "Slack"), ("teams", "Microsoft Teams")]
    STATUS_CHOICES = [("sent", "Sent"), ("failed", "Failed")]

    session = models.ForeignKey("scans.ScanSession", on_delete=models.CASCADE, related_name="alerts")
    alert_type = models.CharField(max_length=20, choices=ALERT_TYPE_CHOICES)
    severity_threshold = models.CharField(max_length=20)
    message = models.TextField(blank=True)
    sent_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, db_index=True)
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ["-sent_at"]

    def __str__(self):
        return f"{self.alert_type} [{self.status}] — {self.sent_at}"
