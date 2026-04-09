from django.contrib import admin
from .models import NucleiFinding


@admin.register(NucleiFinding)
class NucleiAdmin(admin.ModelAdmin):
    list_display = ["template_name", "severity", "host", "cve_id", "session", "discovered_at"]
    list_filter = ["severity", "is_new"]
    search_fields = ["host", "template_id", "template_name", "cve_id"]
    readonly_fields = ["discovered_at"]
