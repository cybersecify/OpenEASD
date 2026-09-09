from django.contrib import admin
from .models import Finding


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ["title", "source", "severity", "status", "target", "session", "discovered_at"]
    list_filter = ["source", "severity", "status", "check_type"]
    search_fields = ["title", "target", "description"]
    readonly_fields = ["discovered_at"]
