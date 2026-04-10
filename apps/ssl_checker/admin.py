from django.contrib import admin
from .models import SSLFinding


@admin.register(SSLFinding)
class SSLFindingAdmin(admin.ModelAdmin):
    list_display = ["domain", "severity", "issue_type", "title", "session", "discovered_at"]
    list_filter = ["severity", "issue_type"]
    search_fields = ["domain", "title"]
    readonly_fields = ["discovered_at"]
