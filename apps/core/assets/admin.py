from django.contrib import admin

from .models import Subdomain, IPAddress, Port


@admin.register(Subdomain)
class SubdomainAdmin(admin.ModelAdmin):
    list_display = ["subdomain", "domain", "source", "session", "discovered_at"]
    list_filter = ["source"]
    search_fields = ["subdomain", "domain"]
    readonly_fields = ["discovered_at"]


@admin.register(IPAddress)
class IPAddressAdmin(admin.ModelAdmin):
    list_display = ["address", "version", "source", "session", "discovered_at"]
    list_filter = ["version", "source"]
    search_fields = ["address"]


@admin.register(Port)
class PortAdmin(admin.ModelAdmin):
    list_display = ["port", "protocol", "state", "service", "source", "session"]
    list_filter = ["protocol", "state", "source"]


