"""OpenEASD URL Configuration."""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include, re_path
from django.views.generic import TemplateView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("apps.core.api.urls")),
    path("reports/", include("apps.core.reports.urls")),
    re_path(
        r'^(?!api/|admin|static/|media/).*$',
        TemplateView.as_view(template_name='index.html'),
        name='spa',
    ),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
