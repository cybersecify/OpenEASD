"""Django admin for scan session models."""

from django.contrib import admin
from django.utils.html import format_html
from .models import ScanSession, ScanDelta


@admin.register(ScanSession)
class ScanSessionAdmin(admin.ModelAdmin):
    list_display = ["id", "domain", "scan_type", "status_badge", "total_findings", "start_time", "end_time"]
    list_filter = ["status", "domain"]
    search_fields = ["domain"]
    readonly_fields = ["start_time", "end_time"]

    def status_badge(self, obj):
        colors = {"pending": "gray", "running": "orange", "completed": "green", "failed": "red"}
        color = colors.get(obj.status, "gray")
        return format_html('<span style="color:{}">{}</span>', color, obj.status.upper())
    status_badge.short_description = "Status"


@admin.register(ScanDelta)
class ScanDeltaAdmin(admin.ModelAdmin):
    list_display = ["id", "change_type", "change_category", "item_identifier", "created_at"]
    list_filter = ["change_type", "change_category"]
    search_fields = ["item_identifier"]
