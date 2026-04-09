from django.contrib import admin
from .models import ServiceResult


@admin.register(ServiceResult)
class ServiceResultAdmin(admin.ModelAdmin):
    list_display = ["host", "port", "protocol", "service_name", "version", "risk_level", "session"]
    list_filter = ["risk_level", "protocol", "state"]
    search_fields = ["host", "service_name"]
    readonly_fields = ["discovered_at"]
