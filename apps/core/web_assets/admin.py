from django.contrib import admin

from .models import URL


@admin.register(URL)
class URLAdmin(admin.ModelAdmin):
    list_display = ["url", "status_code", "source", "session"]
    list_filter = ["source", "status_code"]
    search_fields = ["url"]
