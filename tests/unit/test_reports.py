"""
Unit tests for apps/core/console/reports/views.py

Tests CSV export content/structure. (PDF export was removed.)
"""

import csv
import io

import pytest
from django.contrib.auth.models import User
from django.test import Client
from django.utils import timezone


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def user(db):
    return User.objects.create_user("reportuser", password="x")


@pytest.fixture
def session(db):
    from apps.core.engine.scans.models import ScanSession
    return ScanSession.objects.create(
        domain="report.example.com", scan_type="full", status="completed",
        end_time=timezone.now(), total_findings=3,
    )


@pytest.fixture
def findings(db, session):
    from apps.core.data.findings.models import Finding
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

    def test_hidden_titles_excluded_from_csv(self, authed_client, session):
        from apps.core.data.findings.models import Finding
        for t in ("BIMI not configured", "Domain update lock not enabled", "RDAP lookup failed"):
            Finding.objects.create(session=session, source="domain_security",
                                   target=session.domain, check_type="rdap",
                                   severity="info", title=t, description="d", remediation="r")
        Finding.objects.create(session=session, source="domain_security",
                               target=session.domain, check_type="dnssec",
                               severity="medium", title="DNSSEC not enabled",
                               description="d", remediation="r")
        content = authed_client.get(f"/reports/{session.uuid}/csv/").content.decode("utf-8")
        assert "BIMI not configured" not in content
        assert "Domain update lock not enabled" not in content
        assert "RDAP lookup failed" not in content
        assert "DNSSEC not enabled" in content   # a normal finding still exported

    def test_csv_empty_when_no_findings(self, authed_client, session):
        res = authed_client.get(f"/reports/{session.uuid}/csv/")
        content = res.content.decode("utf-8")
        rows = list(csv.reader(io.StringIO(content)))
        assert len(rows) == 1  # header only

    def test_unauthenticated_redirects(self, session, findings):
        c = Client()
        res = c.get(f"/reports/{session.uuid}/csv/")
        assert res.status_code in (302, 301)

    def test_valid_bearer_token_grants_access(self, session, findings, user):
        from ninja_jwt.tokens import AccessToken
        c = Client()
        token = str(AccessToken.for_user(user))
        res = c.get(f"/reports/{session.uuid}/csv/",
                    HTTP_AUTHORIZATION=f"Bearer {token}")
        assert res.status_code == 200

    def test_query_param_token_ignored(self, session, findings, user):
        # F-sec3: the ?token= query-param auth path was removed (it leaked JWTs
        # into history/Referer/logs). Even a VALID token in the URL must NOT grant
        # access — only the Authorization header (or a session) does.
        from ninja_jwt.tokens import AccessToken
        c = Client()
        token = str(AccessToken.for_user(user))
        res = c.get(f"/reports/{session.uuid}/csv/?token={token}")
        assert res.status_code in (302, 301)  # redirect to /login, not 200

    def test_deactivated_user_token_rejected(self, session, findings, user):
        # A valid-looking token for a since-deactivated user must be refused
        # (the view resolves User.objects.get(id=..., is_active=True)).
        from ninja_jwt.tokens import AccessToken
        token = str(AccessToken.for_user(user))
        user.is_active = False
        user.save()
        c = Client()
        res = c.get(f"/reports/{session.uuid}/csv/",
                    HTTP_AUTHORIZATION=f"Bearer {token}")
        assert res.status_code in (302, 301)

    def test_not_found_returns_404(self, authed_client):
        res = authed_client.get("/reports/00000000-0000-0000-0000-000000000000/csv/")
        assert res.status_code == 404

    def test_min_severity_high_excludes_medium_and_info(self, authed_client, session, findings):
        res = authed_client.get(f"/reports/{session.uuid}/csv/?min_severity=high")
        content = res.content.decode("utf-8")
        assert "TLS expired" in content       # high — included
        assert "No DMARC" not in content      # medium — excluded
        assert "Info finding" not in content  # info — excluded

    def test_min_severity_medium_excludes_info(self, authed_client, session, findings):
        res = authed_client.get(f"/reports/{session.uuid}/csv/?min_severity=medium")
        content = res.content.decode("utf-8")
        assert "TLS expired" in content       # high — included
        assert "No DMARC" in content          # medium — included
        assert "Info finding" not in content  # info — excluded

    def test_min_severity_info_includes_all(self, authed_client, session, findings):
        res = authed_client.get(f"/reports/{session.uuid}/csv/?min_severity=info")
        content = res.content.decode("utf-8")
        rows = list(csv.reader(io.StringIO(content)))
        assert len(rows) == len(findings) + 1  # all findings + header

    def test_min_severity_critical_returns_only_critical(self, authed_client, session, findings):
        res = authed_client.get(f"/reports/{session.uuid}/csv/?min_severity=critical")
        content = res.content.decode("utf-8")
        rows = list(csv.reader(io.StringIO(content)))
        assert len(rows) == 1  # header only — no critical findings in fixture

    def test_invalid_min_severity_returns_400(self, authed_client, session, findings):
        res = authed_client.get(f"/reports/{session.uuid}/csv/?min_severity=bogus")
        assert res.status_code == 400


# ---------------------------------------------------------------------------
# PDF export removed
# ---------------------------------------------------------------------------

class TestPdfRouteRemoved:
    def test_pdf_route_no_longer_resolves(self, authed_client, session):
        res = authed_client.get(f"/reports/{session.uuid}/pdf/")
        assert res.status_code == 404


# ---------------------------------------------------------------------------
# Optional CTA — both REPORT_CTA_URL + REPORT_CTA_TEXT must be set to render
# ---------------------------------------------------------------------------

class TestReportCtaCsv:
    def test_cta_absent_when_neither_setting_configured(self, authed_client, session, findings, settings):
        settings.REPORT_CTA_URL = ""
        settings.REPORT_CTA_TEXT = ""
        res = authed_client.get(f"/reports/{session.uuid}/csv/")
        content = res.content.decode("utf-8")
        rows = list(csv.reader(io.StringIO(content)))
        # 1 header + N findings, no CTA spacer / row
        assert len(rows) == len(findings) + 1

    def test_cta_absent_when_only_url_configured(self, authed_client, session, findings, settings):
        settings.REPORT_CTA_URL = "https://example.com/help"
        settings.REPORT_CTA_TEXT = ""
        res = authed_client.get(f"/reports/{session.uuid}/csv/")
        content = res.content.decode("utf-8")
        assert "https://example.com/help" not in content

    def test_cta_absent_when_only_text_configured(self, authed_client, session, findings, settings):
        settings.REPORT_CTA_URL = ""
        settings.REPORT_CTA_TEXT = "Talk to us"
        res = authed_client.get(f"/reports/{session.uuid}/csv/")
        content = res.content.decode("utf-8")
        assert "Talk to us" not in content

    def test_cta_appended_when_both_configured(self, authed_client, session, findings, settings):
        settings.REPORT_CTA_URL = "https://example.com/help"
        settings.REPORT_CTA_TEXT = "Need help acting on these findings?"
        res = authed_client.get(f"/reports/{session.uuid}/csv/")
        content = res.content.decode("utf-8")
        assert "Need help acting on these findings?" in content
        assert "https://example.com/help" in content


class TestCsvNewFlag:
    def _finding(self, session, title, severity, source, check_type):
        from apps.core.data.findings.models import Finding
        return Finding.objects.create(
            session=session, source=source, check_type=check_type,
            severity=severity, title=title, target="report.example.com",
            description="desc", remediation="fix", status="open",
        )

    def _prev_session(self, domain="report.example.com"):
        from apps.core.engine.scans.models import ScanSession
        return ScanSession.objects.create(
            domain=domain, scan_type="full", status="completed",
            start_time=timezone.now() - timezone.timedelta(days=7),
            end_time=timezone.now() - timezone.timedelta(days=7),
        )

    def test_csv_flags_new_findings(self, authed_client, session):
        prev = self._prev_session()
        self._finding(prev, "Shared", "high", "tls_checker", "tls_expiry")
        self._finding(session, "Shared", "high", "tls_checker", "tls_expiry")
        self._finding(session, "Fresh", "critical", "nuclei", "cve")
        content = authed_client.get(f"/reports/{session.uuid}/csv/").content.decode("utf-8")
        reader = csv.reader(io.StringIO(content))
        header = next(reader)
        assert "New This Scan" in header
        idx = header.index("New This Scan")
        rows = {r[0]: r[idx] for r in reader if r}
        assert rows["Fresh"] == "new"
        assert rows["Shared"] == ""
