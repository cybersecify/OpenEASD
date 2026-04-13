from django.contrib import admin
from .models import NaabuConfig


@admin.register(NaabuConfig)
class NaabuConfigAdmin(admin.ModelAdmin):
    fieldsets = [
        ("Port Selection", {
            "fields": ("top_ports", "custom_ports"),
            "description": "Set Custom Ports to override Top Ports entirely.",
        }),
        ("Performance", {
            "fields": ("rate", "scan_timeout"),
        }),
        ("Exclusions", {
            "fields": ("exclude_ports",),
        }),
    ]

    def has_add_permission(self, request):
        # Only one config row allowed
        return not NaabuConfig.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False
