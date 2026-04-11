"""Scans app URL patterns."""

from django.urls import path
from . import views

urlpatterns = [
    path("start/", views.scan_start, name="scan-start"),
    path("scheduled/", views.scheduled_jobs, name="scheduled-jobs"),
    path("scheduled/<str:job_id>/cancel/", views.cancel_scheduled_job, name="cancel-scheduled-job"),
    path("", views.scan_list, name="scan-list"),
    path("<uuid:session_uuid>/", views.scan_detail, name="scan-detail"),
    path("<uuid:session_uuid>/status/", views.scan_status_fragment, name="scan-status-fragment"),
    path("findings/", views.vulnerability_list, name="finding-list"),
    path("findings/<int:finding_id>/status/", views.finding_update_status, name="finding-update-status"),
]
