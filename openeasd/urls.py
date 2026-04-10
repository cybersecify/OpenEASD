"""OpenEASD URL Configuration."""

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("django.contrib.auth.urls")),
    path("domains/", include("apps.core.domains.urls")),
    path("scans/", include("apps.core.scans.urls")),
    path("workflows/", include("apps.core.workflows.urls")),
    path("insights/", include("apps.core.insights.urls")),
    path("", include("apps.core.dashboard.urls")),
]
