from django.contrib import admin
from .models import SubfinderConfig


@admin.register(SubfinderConfig)
class SubfinderConfigAdmin(admin.ModelAdmin):
    fieldsets = [
        ("ProjectDiscovery", {
            "fields": ("chaos_key",),
            "description": "Chaos dataset — largest passive subdomain source.",
        }),
        ("Internet Search Engines", {
            "fields": ("shodan_key", "censys_id", "censys_secret"),
        }),
        ("DNS / Threat Intel", {
            "fields": ("securitytrails_key", "virustotal_key", "bevigil_key"),
        }),
        ("Code & Infrastructure", {
            "fields": ("github_token", "binaryedge_key", "fullhunt_key", "hunter_key"),
        }),
    ]

    def has_add_permission(self, request):
        return not SubfinderConfig.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False
