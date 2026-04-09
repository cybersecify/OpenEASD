"""Core app views."""

from django.shortcuts import render
from django.db import connection
from django.db.utils import OperationalError

from apps.scans.models import ScanSession


def dashboard(request):
    recent_scans = ScanSession.objects.all()[:10]
    return render(request, "dashboard.html", {"scans": recent_scans})


def health_check(request):
    try:
        connection.ensure_connection()
        db_status = "connected"
    except OperationalError:
        db_status = "disconnected"

    return render(request, "health.html", {
        "db_status": db_status,
        "service": "OpenEASD",
        "version": "1.0.0",
    })
