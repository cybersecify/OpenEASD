"""
Unit tests for apps/core/reports/views.py

Tests CSV export content/structure and PDF export response.
PDF rendering is mocked to avoid the xhtml2pdf dependency in CI.
"""

import csv
import io
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth.models import User
from django.test import Client
from django.utils import timezone

from apps.core.api.auth import create_access_token


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def user(db):
    return User.objects.create_user("reportuser", password="x")


@pytest.fixture
def session(db):
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(
        domain="report.example.com", scan_type="full", status="completed",
        end_time=timezone.now(), total_findings=3,
    )


@pytest.fixture
def findings(db, session):
    from apps.core.findings.models import Finding
    data = [
        ("TLS expired", "high", "tls_checker", "tls_expiry", "open"),
        ("No DMARC",    "medium", "domain_security", "dmarc", "open"),
        ("Info finding", "info", "web_checker", "x_frame", "acknowledged"),
    ]
    result = []
    for title, severity, source, check_type, status in data:
        result.append(Finding.objects.create(
            session=session, source=source, check_type=check_type,
            severity=severity, title=title, target="report.example.com",
            description="desc", remediation="fix", status=status,
        ))
    return result


@pytest.fixture
def authed_client(user):
    """Django test client with a logged-in session (reports use login_required)."""
    c = Client()
    c.force_login(user)
    return c


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

class TestExportFindingsCsv:
    def test_returns_200(self, authed_client, session, findings):
        res = authed_client.get(f"/reports/{session.uuid}/csv/")
        assert res.status_code == 200

    def test_content_type_is_csv(self, authed_client, session, findings):
        res = authed_client.get(f"/reports/{session.uuid}/csv/")
        assert "text/csv" in res["Content-Type"]

    def test_content_disposition_has_filename(self, authed_client, session, findings):
        res = authed_client.get(f"/reports/{session.uuid}/csv/")
        assert "attachment" in res["Content-Disposition"]
        assert "findings_" in res["Content-Disposition"]
        assert session.domain in res["Content-Disposition"]

    def test_csv_has_header_row(self, authed_client, session, findings):
        res = authed_client.get(f"/reports/{session.uuid}/csv/")
        content = res.content.decode("utf-8")
        reader = csv.reader(io.StringIO(content))
        header = next(reader)
        assert "Title" in header
        assert "Severity" in header
        assert "Source" in header
        assert "Status" in header
        assert "Description" in header
        assert "Remediation" in header

    def test_csv_row_count_matches_findings(self, authed_client, session, findings):
        res = authed_client.get(f"/reports/{session.uuid}/csv/")
        content = res.content.decode("utf-8")
        rows = list(csv.reader(io.StringIO(content)))
        # 1 header + N findings
        assert len(rows) == len(findings) + 1

    def test_csv_contains_finding_titles(self, authed_client, session, findings):
        res = authed_client.get(f"/reports/{session.uuid}/csv/")
        content = res.content.decode("utf-8")
        assert "TLS expired" in content
        assert "No DMARC" in content

    def test_csv_empty_when_no_findings(self, authed_client, session):
        res = authed_client.get(f"/reports/{session.uuid}/csv/")
        content = res.content.decode("utf-8")
        rows = list(csv.reader(io.StringIO(content)))
        assert len(rows) == 1  # header only

    def test_unauthenticated_redirects(self, session, findings):
        c = Client()
        res = c.get(f"/reports/{session.uuid}/csv/")
        assert res.status_code in (302, 301)

    def test_not_found_returns_404(self, authed_client):
        res = authed_client.get("/reports/00000000-0000-0000-0000-000000000000/csv/")
        assert res.status_code == 404


# ---------------------------------------------------------------------------
# PDF export
# ---------------------------------------------------------------------------

class TestExportScanPdf:
    def test_returns_200_with_mocked_pdf(self, authed_client, session, findings):
        fake_result = MagicMock()
        fake_result.err = 0

        with patch("xhtml2pdf.pisa.CreatePDF", return_value=fake_result):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert res.status_code == 200

    def test_content_type_is_pdf(self, authed_client, session, findings):
        fake_result = MagicMock()
        fake_result.err = 0

        with patch("xhtml2pdf.pisa.CreatePDF", return_value=fake_result):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert "application/pdf" in res["Content-Type"]

    def test_content_disposition_has_filename(self, authed_client, session, findings):
        fake_result = MagicMock()
        fake_result.err = 0

        with patch("xhtml2pdf.pisa.CreatePDF", return_value=fake_result):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert "attachment" in res["Content-Disposition"]
        assert "scan_report_" in res["Content-Disposition"]

    def test_pdf_error_returns_500(self, authed_client, session, findings):
        fake_result = MagicMock()
        fake_result.err = 1  # pisa error

        with patch("xhtml2pdf.pisa.CreatePDF", return_value=fake_result):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert res.status_code == 500

    def test_unauthenticated_redirects(self, session):
        c = Client()
        res = c.get(f"/reports/{session.uuid}/pdf/")
        assert res.status_code in (302, 301)

    def test_not_found_returns_404(self, authed_client):
        with patch("xhtml2pdf.pisa.CreatePDF", return_value=MagicMock(err=0)):
            res = authed_client.get("/reports/00000000-0000-0000-0000-000000000000/pdf/")
        assert res.status_code == 404
