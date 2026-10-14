"""OpenEASD URL Configuration."""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect
from django.urls import path, include, re_path

from apps.core.console.api.ninja import api


def metrics(request):
    """Prometheus metrics (H2). Unauthenticated (counts only, no finding detail) and
    therefore OPT-IN: OFF by default (M3) — enable METRICS_ENABLED only once the
    endpoint is network-restricted to your scraper. Served by the web tier but
    reflects worker state too (DB-backed exporter)."""
    if not getattr(settings, "METRICS_ENABLED", False):
        return HttpResponse(status=404)
    from apps.core.console.observability.metrics import render_metrics

    resp = HttpResponse(render_metrics(), content_type="text/plain; version=0.0.4")
    resp["Cache-Control"] = "no-store"
    return resp


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


def favicon(request):
    return HttpResponse(status=204)


def catch_all(request):
    """Unmatched non-API paths land on the dashboard."""
    return redirect("mvp:dashboard")


urlpatterns = [
    path("health/", health),
    path("favicon.ico", favicon),
    path("metrics/", metrics),
    path("admin/", admin.site.urls),
    path("api/", api.urls),  # dormant: kept routed, unused by the UI (Option B deferral)
    path("reports/", include("apps.core.console.reports.urls")),
    path("login/", auth_views.LoginView.as_view(), name="login"),
    path("logout/", auth_views.LogoutView.as_view(next_page="login"), name="logout"),
    path("", include("apps.mvp.urls")),
    re_path(r"^(?!api/|admin|static/|media/|metrics/|reports/|login/|logout/).*$", catch_all),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
