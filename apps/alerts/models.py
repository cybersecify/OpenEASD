from django.db import models


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
