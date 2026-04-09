"""OpenEASD URL Configuration."""

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("scans/", include("apps.scans.urls")),
    path("workflows/", include("apps.workflow.urls")),
    path("", include("apps.core.urls")),
]
