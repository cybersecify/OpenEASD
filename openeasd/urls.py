"""OpenEASD URL Configuration."""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.http import JsonResponse
from django.urls import path, include, re_path
from django.views.generic import TemplateView

from apps.core.api.ninja import api


def health(request):
    resp = JsonResponse({
        "status": "ok",
        "version": settings.OPENEASD_VERSION,
        "git_sha": settings.OPENEASD_GIT_SHA[:8],
        "build_date": settings.OPENEASD_BUILD_DATE,
    })
    # Never let a CDN/proxy cache provenance — a cached response makes the app
    # report a stale build after a redeploy (Cloudflare cached /api/version/).
    resp["Cache-Control"] = "no-store"
    return resp


urlpatterns = [
    path("health/", health),
    path("admin/", admin.site.urls),
    path("api/", api.urls),
    path("reports/", include("apps.core.reports.urls")),
    re_path(
        r'^(?!api/|admin|static/|media/).*$',
        TemplateView.as_view(template_name='index.html'),
        name='spa',
    ),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
