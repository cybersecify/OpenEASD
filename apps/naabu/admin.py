from django.contrib import admin
from .models import PortResult


@admin.register(PortResult)
class PortResultAdmin(admin.ModelAdmin):
    list_display = ["host", "port", "protocol", "state", "session", "discovered_at"]
    list_filter = ["protocol", "state"]
    search_fields = ["host"]
    readonly_fields = ["discovered_at"]
