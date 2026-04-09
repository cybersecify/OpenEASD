from django.contrib import admin
from .models import EmailFinding


@admin.register(EmailFinding)
class EmailFindingAdmin(admin.ModelAdmin):
    list_display = ["domain", "check_type", "severity", "title", "session", "discovered_at"]
    list_filter = ["severity", "check_type"]
    search_fields = ["domain", "title"]
    readonly_fields = ["discovered_at"]
