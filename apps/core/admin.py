from django.contrib import admin
from .models import ScanConfiguration


@admin.register(ScanConfiguration)
class ScanConfigurationAdmin(admin.ModelAdmin):
    list_display = ["domain", "config_name", "is_active", "updated_at"]
    list_filter = ["is_active", "domain"]
    search_fields = ["domain", "config_name"]
