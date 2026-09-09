from django.contrib import admin

from .models import ToolCredentials


@admin.register(ToolCredentials)
class ToolCredentialsAdmin(admin.ModelAdmin):
    list_display = ("__str__", "updated_at")
