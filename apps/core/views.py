"""Core views: health check and root endpoint."""

from django.db import connection
from rest_framework.decorators import api_view
from rest_framework.response import Response


@api_view(["GET"])
def health_check(request):
    """Health check endpoint."""
    db_status = "connected"
    try:
        connection.ensure_connection()
    except Exception:
        db_status = "disconnected"

    return Response({
        "status": "healthy",
        "service": "OpenEASD",
        "version": "1.0.0",
        "database": db_status,
    })


@api_view(["GET"])
def root(request):
    """Root endpoint."""
    return Response({
        "message": "Welcome to OpenEASD - Automated External Attack Surface Detection",
        "company": "Cybersecify",
        "author": "Rathnakara G N",
        "version": "1.0.0",
        "docs": "/api/",
        "health": "/health",
    })
