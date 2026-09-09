from django.contrib import admin
from .models import ScanSummary, FindingTypeSummary


@admin.register(ScanSummary)
class ScanSummaryAdmin(admin.ModelAdmin):
    list_display = ["domain", "scan_date", "critical_count", "high_count", "medium_count", "low_count", "total_findings"]
    list_filter = ["domain"]
    readonly_fields = ["session", "domain", "scan_date", "tool_breakdown"]


@admin.register(FindingTypeSummary)
class FindingTypeSummaryAdmin(admin.ModelAdmin):
    list_display = ["title", "check_type", "severity", "occurrence_count", "last_seen"]
    list_filter = ["severity", "check_type"]
