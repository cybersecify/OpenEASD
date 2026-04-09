"""
DRF views for OpenEASD scan management.

Replaces the original FastAPI endpoints in main.py.
"""

import logging

from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import ScanSession, Vulnerability
from .serializers import (
    ScanSessionSerializer,
    ScanSessionDetailSerializer,
    StartScanSerializer,
    VulnerabilitySerializer,
)
from .tasks import run_scan

logger = logging.getLogger(__name__)


@api_view(["POST"])
def start_scan(request):
    """
    Start a security scan for a domain.

    POST /api/scan/start/
    Body: {"domain": "example.com", "scan_type": "full"}
    """
    serializer = StartScanSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    domain = serializer.validated_data["domain"].strip()
    scan_type = serializer.validated_data["scan_type"]

    # Create session record immediately
    session = ScanSession.objects.create(domain=domain, scan_type=scan_type)

    # Dispatch Celery task
    task = run_scan.delay(session.id)
    logger.info(f"Scan started: session={session.id} domain={domain} task={task.id}")

    return Response(
        {
            "message": f"Scan started for domain: {domain}",
            "session_id": session.id,
            "scan_type": scan_type,
            "status": "initiated",
            "task_id": task.id,
        },
        status=status.HTTP_202_ACCEPTED,
    )


@api_view(["GET"])
def scan_status(request, session_id):
    """
    Get status of a scan session.

    GET /api/scan/<session_id>/status/
    """
    session = get_object_or_404(ScanSession, id=session_id)
    serializer = ScanSessionSerializer(session)

    data = serializer.data
    data["vulnerability_counts"] = {
        sev: session.vulnerabilities.filter(severity=sev).count()
        for sev in ["critical", "high", "medium", "low"]
    }
    return Response(data)


@api_view(["GET"])
def scan_results(request, session_id):
    """
    Get full results of a completed scan session.

    GET /api/scan/<session_id>/results/
    """
    session = get_object_or_404(ScanSession, id=session_id)

    if session.status == "running":
        return Response(
            {"detail": "Scan is still running", "status": "running"},
            status=status.HTTP_202_ACCEPTED,
        )

    serializer = ScanSessionDetailSerializer(session)
    return Response(serializer.data)


@api_view(["GET"])
def list_scans(request):
    """
    List all scan sessions.

    GET /api/scans/?domain=example.com&status=completed
    """
    qs = ScanSession.objects.all()

    domain = request.query_params.get("domain")
    if domain:
        qs = qs.filter(domain=domain)

    status_filter = request.query_params.get("status")
    if status_filter:
        qs = qs.filter(status=status_filter)

    serializer = ScanSessionSerializer(qs[:50], many=True)
    return Response({"count": qs.count(), "results": serializer.data})


@api_view(["GET"])
def vulnerability_list(request):
    """
    List vulnerabilities with optional filtering.

    GET /api/vulnerabilities/?severity=critical&session_id=1
    """
    qs = Vulnerability.objects.select_related("session")

    severity = request.query_params.get("severity")
    if severity:
        qs = qs.filter(severity=severity)

    session_id = request.query_params.get("session_id")
    if session_id:
        qs = qs.filter(session_id=session_id)

    domain = request.query_params.get("domain")
    if domain:
        qs = qs.filter(session__domain=domain)

    serializer = VulnerabilitySerializer(qs[:100], many=True)
    return Response({"count": qs.count(), "results": serializer.data})
