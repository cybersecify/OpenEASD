from django.urls import path

from . import views

app_name = "mvp"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("change-password/", views.change_password, name="change-password"),
    path("activity/", views.dashboard_activity, name="activity"),
    path("domains/", views.domains, name="domains"),
    path("domains/add/", views.domain_create, name="domain-create"),
    path("scans/", views.scans, name="scans"),
    path("scan/start/", views.scan_start, name="scan-start"),
    path("scan/<uuid:session_uuid>/", views.scan_detail, name="scan-detail"),
    path("scan/<uuid:session_uuid>/progress/", views.scan_progress, name="scan-progress"),
    path("scan/<uuid:session_uuid>/cancel/", views.scan_cancel, name="scan-cancel"),
    path("domains/<str:name>/", views.domain_detail, name="domain-detail"),
    path("domains/<str:name>/authorize/", views.domain_authorize, name="domain-authorize"),
    path("domains/<str:name>/monitoring/", views.domain_monitoring, name="domain-monitoring"),
    path("domains/<str:name>/delete/", views.domain_delete, name="domain-delete"),
]
