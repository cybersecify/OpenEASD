from django.contrib import admin

from .models import NmapFinding


@admin.register(NmapFinding)
class NmapFindingAdmin(admin.ModelAdmin):
    list_display = ["title", "address", "port_number", "severity", "cvss_score", "cve", "session"]
    list_filter = ["severity", "nse_script"]
    search_fields = ["title", "address", "cve"]
    readonly_fields = ["discovered_at"]
