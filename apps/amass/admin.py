from django.contrib import admin
from .models import AmassConfig


@admin.register(AmassConfig)
class AmassConfigAdmin(admin.ModelAdmin):
    fieldsets = [
        ("Control", {
            "fields": ("enabled", "wordlist_file", "scan_timeout"),
            "description": (
                "Amass runs active DNS enumeration (zone transfers, brute force). "
                "Disable here without touching your workflow configuration."
            ),
        }),
        ("ProjectDiscovery", {
            "fields": ("chaos_key",),
            "classes": ("collapse",),
        }),
        ("Internet Search Engines", {
            "fields": ("shodan_key", "censys_id", "censys_secret"),
            "classes": ("collapse",),
        }),
        ("DNS / Threat Intel", {
            "fields": ("securitytrails_key", "virustotal_key"),
            "classes": ("collapse",),
        }),
        ("Passive DNS & WHOIS", {
            "fields": ("passivetotal_username", "passivetotal_key", "whoisxmlapi_key"),
            "classes": ("collapse",),
            "description": "PassiveTotal (RiskIQ) and WhoisXMLAPI are unique to amass.",
        }),
        ("Code Hosting", {
            "fields": ("github_token",),
            "classes": ("collapse",),
        }),
    ]

    def has_add_permission(self, request):
        return not AmassConfig.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False
