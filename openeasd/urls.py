"""OpenEASD URL Configuration."""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.http import JsonResponse
from django.shortcuts import render
from django.urls import path, include, re_path

from apps.core.console.api.ninja import api


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


def spa(request):
    """Serve the SPA entry point with no caching.

    index.html references content-hashed JS/CSS bundles, so a CDN/browser that
    caches it keeps serving the OLD bundle (stale UI) after a deploy even though
    the backend is new — exactly what happened when Cloudflare cached index.html
    with max-age=3600 and showed the pre-release UI post-v2.10.0. The hashed
    assets under /static/ stay long-cached (WhiteNoise); only this mutable entry
    point must always revalidate. Same class of fix as /health above.
    """
    resp = render(request, "index.html")
    resp["Cache-Control"] = "no-store"
    return resp


urlpatterns = [
    path("health/", health),
    path("admin/", admin.site.urls),
    path("api/", api.urls),
    path("reports/", include("apps.core.console.reports.urls")),
    re_path(r'^(?!api/|admin|static/|media/).*$', spa, name='spa'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
