from django.contrib import admin

from .models import Subdomain, IPAddress, Port, URL, Technology, Certificate


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


@admin.register(URL)
class URLAdmin(admin.ModelAdmin):
    list_display = ["url", "status_code", "source", "session"]
    list_filter = ["source", "status_code"]
    search_fields = ["url"]


@admin.register(Technology)
class TechnologyAdmin(admin.ModelAdmin):
    list_display = ["name", "version", "category", "source", "session"]
    list_filter = ["category", "source"]
    search_fields = ["name"]


@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    list_display = ["domain", "issuer", "valid_to", "is_expired", "session"]
    list_filter = ["is_expired", "source"]
    search_fields = ["domain", "issuer"]
