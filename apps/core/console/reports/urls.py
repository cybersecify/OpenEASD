"""Reports app URL patterns."""

from django.urls import path
from . import views

urlpatterns = [
    path("<uuid:session_uuid>/csv/", views.export_findings_csv, name="export-csv"),
    path("<uuid:session_uuid>/pdf/", views.export_scan_pdf, name="export-pdf"),
]
