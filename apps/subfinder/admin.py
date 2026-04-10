from django.contrib import admin
from .models import Subdomain


@admin.register(Subdomain)
class SubdomainAdmin(admin.ModelAdmin):
    list_display = ["subdomain", "ip_address", "session", "is_active", "discovered_at"]
    list_filter = ["is_active"]
    search_fields = ["subdomain", "ip_address"]
    readonly_fields = ["discovered_at"]
