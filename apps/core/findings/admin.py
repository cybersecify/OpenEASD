from django.contrib import admin
from .models import Finding


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ["title", "source", "severity", "target", "session", "discovered_at"]
    list_filter = ["source", "severity", "check_type"]
    search_fields = ["title", "target", "description"]
    readonly_fields = ["discovered_at"]
