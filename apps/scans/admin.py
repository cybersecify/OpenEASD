"""Django admin for scan models."""

from django.contrib import admin
from django.utils.html import format_html
from .models import ScanSession, Subdomain, Service, Vulnerability, Alert, ScanDelta


class SubdomainInline(admin.TabularInline):
    model = Subdomain
    extra = 0
    readonly_fields = ["subdomain", "ip_address", "discovered_at"]


class ServiceInline(admin.TabularInline):
    model = Service
    extra = 0
    readonly_fields = ["host", "port", "service_name", "version", "risk_level"]


class VulnerabilityInline(admin.TabularInline):
    model = Vulnerability
    extra = 0
    readonly_fields = ["severity", "title", "host", "vulnerability_type"]


@admin.register(ScanSession)
class ScanSessionAdmin(admin.ModelAdmin):
    list_display = ["id", "domain", "scan_type", "status_badge", "total_findings", "start_time", "end_time"]
    list_filter = ["status", "scan_type", "domain"]
    search_fields = ["domain"]
    readonly_fields = ["start_time", "end_time", "created_at", "config_hash"]
    inlines = [SubdomainInline, ServiceInline, VulnerabilityInline]

    def status_badge(self, obj):
        colors = {"running": "orange", "completed": "green", "failed": "red"}
        color = colors.get(obj.status, "gray")
        return format_html('<span style="color:{}">{}</span>', color, obj.status.upper())
    status_badge.short_description = "Status"


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ["id", "severity", "title", "host", "vulnerability_type", "cve_id", "discovered_at"]
    list_filter = ["severity", "vulnerability_type", "is_new"]
    search_fields = ["host", "title", "cve_id", "vulnerability_type"]
    readonly_fields = ["discovered_at"]


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ["id", "host", "port", "protocol", "service_name", "risk_level", "state"]
    list_filter = ["risk_level", "protocol", "state"]
    search_fields = ["host", "service_name"]


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ["id", "alert_type", "status", "severity_threshold", "sent_at", "retry_count"]
    list_filter = ["status", "alert_type"]
    readonly_fields = ["sent_at"]


@admin.register(ScanDelta)
class ScanDeltaAdmin(admin.ModelAdmin):
    list_display = ["id", "change_type", "change_category", "item_identifier", "created_at"]
    list_filter = ["change_type", "change_category"]
    search_fields = ["item_identifier"]
