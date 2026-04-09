"""Scans app URL patterns."""

from django.urls import path
from . import views

urlpatterns = [
    path("scan/start/", views.start_scan, name="scan-start"),
    path("scan/<int:session_id>/status/", views.scan_status, name="scan-status"),
    path("scan/<int:session_id>/results/", views.scan_results, name="scan-results"),
    path("scans/", views.list_scans, name="scan-list"),
    path("vulnerabilities/", views.vulnerability_list, name="vulnerability-list"),
]
