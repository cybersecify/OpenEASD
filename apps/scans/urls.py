"""Scans app URL patterns."""

from django.urls import path
from . import views

urlpatterns = [
    path("start/", views.scan_start, name="scan-start"),
    path("", views.scan_list, name="scan-list"),
    path("<int:session_id>/", views.scan_detail, name="scan-detail"),
    path("<int:session_id>/status/", views.scan_status_fragment, name="scan-status-fragment"),
    path("vulnerabilities/", views.vulnerability_list, name="vulnerability-list"),
]
