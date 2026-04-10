from django.contrib import admin
from .models import Alert


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ["session", "alert_type", "status", "severity_threshold", "sent_at"]
    list_filter = ["status", "alert_type", "severity_threshold"]
    readonly_fields = ["sent_at"]
    search_fields = ["session__domain"]
