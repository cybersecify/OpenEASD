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


class TestReportCtaPdfContext:
    """The PDF view passes report_cta_url/report_cta_text into the template
    context only when configured. Verified by mocking pisa and inspecting
    the rendered HTML before PDF conversion."""

    def test_cta_context_empty_when_settings_empty(self, authed_client, session, findings, settings):
        settings.REPORT_CTA_URL = ""
        settings.REPORT_CTA_TEXT = ""
        captured = {}

        def capture_html(html_str, dest):
            captured["html"] = html_str
            mock = MagicMock()
            mock.err = 0
            return mock

        with patch("xhtml2pdf.pisa.CreatePDF", side_effect=capture_html):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert res.status_code == 200
        assert "report-cta" not in captured["html"]

    def test_cta_renders_in_html_when_both_set(self, authed_client, session, findings, settings):
        settings.REPORT_CTA_URL = "https://example.com/help"
        settings.REPORT_CTA_TEXT = "Need help acting on these findings?"
        captured = {}

        def capture_html(html_str, dest):
            captured["html"] = html_str
            mock = MagicMock()
            mock.err = 0
            return mock

        with patch("xhtml2pdf.pisa.CreatePDF", side_effect=capture_html):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert res.status_code == 200
        assert "report-cta" in captured["html"]
        assert "Need help acting on these findings?" in captured["html"]
        assert "https://example.com/help" in captured["html"]


class TestPdfSeverityCounts:
    """Regression: the severity summary must count EVERY finding, not collapse
    to one per severity. The findings queryset is ordered by
    (severity, -discovered_at); that trailing sort field must not leak into the
    GROUP BY of the per-severity Count(), or every bucket collapses to 1."""

    def test_counts_all_findings_per_severity(self, authed_client, session):
        from apps.core.findings.models import Finding
        for sev, n in [("critical", 2), ("high", 3)]:
            for i in range(n):
                Finding.objects.create(
                    session=session, source="tls_checker", check_type="x",
                    severity=sev, title=f"{sev}-{i}", target="report.example.com",
                    description="d", remediation="f", status="open",
                )
        captured = {}

        def capture_html(html_str, dest):
            captured["html"] = html_str
            mock = MagicMock()
            mock.err = 0
            return mock

        with patch("xhtml2pdf.pisa.CreatePDF", side_effect=capture_html):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert res.status_code == 200
        html = captured["html"]
        # Correct counts — would render 1/1/2 under the GROUP BY leak bug.
        assert '<div class="metric-num c-critical">2</div>' in html
        assert '<div class="metric-num c-high">3</div>' in html
        assert '<div class="metric-num">5</div>' in html

    def test_headline_tiles_show_unique_not_raw(self, authed_client, session):
        """Tiles + risk reflect consolidated unique issues, not raw detections;
        the raw count appears only in the consolidation note."""
        from apps.core.findings.models import Finding
        for ip in ("1.1.1.1:443", "2.2.2.2:443", "3.3.3.3:443"):
            Finding.objects.create(
                session=session, source="tls_checker", check_type="unencrypted_service",
                severity="critical", title=f"Unencrypted HTTPS on {ip}", target=ip,
                description="d", remediation="r", status="open",
            )
        captured = {}

        def capture_html(html_str, dest):
            captured["html"] = html_str
            mock = MagicMock()
            mock.err = 0
            return mock

        with patch("xhtml2pdf.pisa.CreatePDF", side_effect=capture_html):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert res.status_code == 200
        html = captured["html"]
        # 3 raw detections consolidate to 1 unique critical issue.
        assert '<div class="metric-num c-critical">1</div>' in html
        assert '<div class="metric-num">1</div>' in html  # total tile = unique
        assert "3 raw scanner detections into 1 unique issue" in html


class TestFindingGrouping:
    """Repeated issues (identical write-up across targets) collapse into one
    block with a table of affected targets, instead of one full card each."""

    def _mk(self, session, **kw):
        from apps.core.findings.models import Finding
        base = dict(
            session=session, source="tls_checker", check_type="unencrypted_service",
            severity="critical", target="1.1.1.1:443", description="Plaintext service.",
            remediation="Enable TLS.", status="open", title="Unencrypted HTTPS on 1.1.1.1:443",
        )
        base.update(kw)
        return Finding.objects.create(**base)

    def test_identical_writeups_collapse_and_strip_target(self, db, session):
        from apps.core.reports.views import _group_findings_by_issue
        from apps.core.findings.models import Finding
        for ip in ("1.1.1.1:443", "2.2.2.2:443", "3.3.3.3:443"):
            self._mk(session, target=ip, title=f"Unencrypted HTTPS on {ip}")
        self._mk(session, source="web_checker", check_type="missing_csp", severity="high",
                 target="http://x:80", title="Missing CSP on http://x:80",
                 description="No CSP header.", remediation="Add CSP.")
        findings = Finding.objects.filter(session=session).order_by("severity", "-discovered_at")
        groups = _group_findings_by_issue(findings)

        assert len(groups) == 2  # 3 identical collapse to 1; the unique one stands alone
        crit = next(g for g in groups if g["severity"] == "critical")
        assert crit["title"] == "Unencrypted HTTPS"        # " on <target>" stripped
        assert len(crit["instances"]) == 3
        high = next(g for g in groups if g["severity"] == "high")
        assert high["title"] == "Missing CSP"
        assert len(high["instances"]) == 1

    def test_pdf_renders_description_once_not_per_instance(self, authed_client, session):
        for ip in ("1.1.1.1:443", "2.2.2.2:443", "3.3.3.3:443"):
            self._mk(session, target=ip, title=f"Unencrypted HTTPS on {ip}")
        captured = {}

        def capture_html(html_str, dest):
            captured["html"] = html_str
            mock = MagicMock()
            mock.err = 0
            return mock

        with patch("xhtml2pdf.pisa.CreatePDF", side_effect=capture_html):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert res.status_code == 200
        html = captured["html"]
        # Description block rendered once for the group, not once per target.
        assert html.count("Plaintext service.") == 1
        # But all three targets are still listed under Affected Targets.
        for ip in ("1.1.1.1:443", "2.2.2.2:443", "3.3.3.3:443"):
            assert ip in html


class TestReportEnrichment:
    """Scope / CWE / CVSS / ID enrichment applied to issue groups."""

    def test_risk_rating_uses_highest_populated_severity(self):
        from apps.core.reports.views import _risk_rating
        assert _risk_rating({"critical": 2, "high": 1}) == "CRITICAL"
        assert _risk_rating({"critical": 0, "high": 3, "medium": 1}) == "HIGH"
        assert _risk_rating({"medium": 4}) == "MEDIUM"
        assert _risk_rating({"low": 1}) == "LOW"
        assert _risk_rating({"critical": 0, "high": 0}) == "INFORMATIONAL"

    def test_finding_scope_check_type_overrides_source(self):
        from apps.core.reports.views import _finding_scope
        assert _finding_scope("domain_security", "rdap") == "Domain"       # check_type wins
        assert _finding_scope("domain_security", "dmarc") == "Email / DNS"  # source fallback
        assert _finding_scope("tls_checker", "san_mismatch") == "TLS / HTTPS"
        assert _finding_scope("mystery", "unknown") == "General"

    def test_group_carries_id_scope_cwe_cvss_cves(self, db, session):
        from apps.core.reports.views import _group_findings_by_issue
        from apps.core.findings.models import Finding
        Finding.objects.create(
            session=session, source="nmap", check_type="cve", severity="high",
            title="OpenSSH CVEs on 1.1.1.1:22", target="1.1.1.1:22",
            description="d", remediation="r", status="open",
            extra={"cvss_score": 8.1, "cve_ids": ["CVE-2026-1", "CVE-2026-2"]},
        )
        Finding.objects.create(
            session=session, source="tls_checker", check_type="san_mismatch", severity="medium",
            title="SAN mismatch on 2.2.2.2:443", target="2.2.2.2:443",
            description="d2", remediation="r2", status="open",
        )
        groups = _group_findings_by_issue(
            Finding.objects.filter(session=session).order_by("severity", "-discovered_at")
        )
        by_check = {g["check_type"]: g for g in groups}
        cve = by_check["cve"]
        assert cve["fid"].startswith("OE-") and cve["fid"].endswith("001")  # first after sort
        assert cve["scope"] == "Network"
        assert cve["cvss"] == 8.1                       # real CVSS from extra
        assert cve["cves"] == ["CVE-2026-1", "CVE-2026-2"]
        san = by_check["san_mismatch"]
        assert san["cvss"] == 5.3                        # severity-band default (medium)
        assert san["cwe"].startswith("CWE-295")
        # endpoints chunked into rows of 3 for the pill grid
        assert cve["endpoint_rows"] == [["1.1.1.1:22"]]

    def test_methodology_and_endpoint_pills_render(self, authed_client, session):
        from apps.core.findings.models import Finding
        for ip in ("1.1.1.1:443", "2.2.2.2:443"):
            Finding.objects.create(
                session=session, source="tls_checker", check_type="san_mismatch",
                severity="high", title=f"SAN mismatch on {ip}", target=ip,
                description="d", remediation="r", status="open",
            )
        captured = {}

        def capture_html(html_str, dest):
            captured["html"] = html_str
            mock = MagicMock()
            mock.err = 0
            return mock

        with patch("xhtml2pdf.pisa.CreatePDF", side_effect=capture_html):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert res.status_code == 200
        html = captured["html"]
        assert "Scope &amp; Methodology" in html
        assert "Network Exposure" in html          # a registry phase group
        assert 'class="ep-cell"' in html           # endpoints render as a pill grid
