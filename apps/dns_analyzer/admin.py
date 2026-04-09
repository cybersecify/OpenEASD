from django.contrib import admin
from .models import DNSFinding


@admin.register(DNSFinding)
class DNSFindingAdmin(admin.ModelAdmin):
    list_display = ["domain", "record_type", "severity", "title", "session", "discovered_at"]
    list_filter = ["severity", "record_type"]
    search_fields = ["domain", "title"]
    readonly_fields = ["discovered_at"]
