"""
Unit tests for apps/core/console/reports/views.py

Tests CSV export content/structure and PDF export response.
PDF rendering is mocked (via _render_pdf) so tests need no WeasyPrint libs.
"""

import csv
import io
from unittest.mock import patch

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

    def test_garbage_token_rejected(self, session, findings):
        c = Client()
        res = c.get(f"/reports/{session.uuid}/csv/?token=not.a.jwt")
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
# PDF export
# ---------------------------------------------------------------------------

class TestExportScanPdf:
    def test_returns_200_with_mocked_pdf(self, authed_client, session, findings):
        with patch("apps.core.console.reports.views._render_pdf", return_value=b"%PDF-1.7"):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert res.status_code == 200

    def test_content_type_is_pdf(self, authed_client, session, findings):
        with patch("apps.core.console.reports.views._render_pdf", return_value=b"%PDF-1.7"):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert "application/pdf" in res["Content-Type"]

    def test_content_disposition_has_filename(self, authed_client, session, findings):
        with patch("apps.core.console.reports.views._render_pdf", return_value=b"%PDF-1.7"):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert "attachment" in res["Content-Disposition"]
        assert "scan_report_" in res["Content-Disposition"]

    def test_pdf_error_returns_500(self, authed_client, session, findings):
        with patch("apps.core.console.reports.views._render_pdf", side_effect=RuntimeError("render failed")):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert res.status_code == 500

    def test_unauthenticated_redirects(self, session):
        c = Client()
        res = c.get(f"/reports/{session.uuid}/pdf/")
        assert res.status_code in (302, 301)

    def test_not_found_returns_404(self, authed_client):
        with patch("apps.core.console.reports.views._render_pdf", return_value=b"%PDF-1.7"):
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
    context only when configured. Verified by mocking the renderer and inspecting
    the rendered HTML before PDF conversion."""

    def test_cta_context_empty_when_settings_empty(self, authed_client, session, findings, settings):
        settings.REPORT_CTA_URL = ""
        settings.REPORT_CTA_TEXT = ""
        captured = {}

        def capture_html(html):
            captured["html"] = html
            return b"%PDF-1.7"

        with patch("apps.core.console.reports.views._render_pdf", side_effect=capture_html):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert res.status_code == 200
        assert "report-cta" not in captured["html"]

    def test_cta_renders_in_html_when_both_set(self, authed_client, session, findings, settings):
        settings.REPORT_CTA_URL = "https://example.com/help"
        settings.REPORT_CTA_TEXT = "Need help acting on these findings?"
        captured = {}

        def capture_html(html):
            captured["html"] = html
            return b"%PDF-1.7"

        with patch("apps.core.console.reports.views._render_pdf", side_effect=capture_html):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert res.status_code == 200
        assert "report-cta" in captured["html"]
        assert "Need help acting on these findings?" in captured["html"]
        assert "https://example.com/help" in captured["html"]


@pytest.mark.django_db
class TestTechnologyStackBlock:
    """The report renders a Technology Stack block only when web assets were
    fingerprinted (httpx -tech-detect). Distinct techs are aggregated across
    all URLs, deduped, and sorted."""

    def _capture(self, authed_client, session):
        captured = {}

        def capture_html(html):
            captured["html"] = html
            return b"%PDF-1.7"

        with patch("apps.core.console.reports.views._render_pdf", side_effect=capture_html):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")
        assert res.status_code == 200
        return captured["html"]

    def _url(self, session, url, technologies):
        from apps.core.data.web_assets.models import URL
        return URL.objects.create(
            session=session, url=url, host="report.example.com",
            source="httpx", technologies=technologies,
        )

    def test_absent_when_no_technologies(self, authed_client, session, findings):
        # URLs with no fingerprints must not render the block.
        self._url(session, "https://report.example.com/", [])
        html = self._capture(authed_client, session)
        assert "Technology Stack" not in html

    def test_absent_when_no_urls(self, authed_client, session, findings):
        html = self._capture(authed_client, session)
        assert "Technology Stack" not in html

    def test_present_and_aggregated_when_technologies(self, authed_client, session, findings):
        self._url(session, "https://report.example.com/", ["Nginx", "PHP"])
        self._url(session, "https://www.report.example.com/", ["WordPress", "nginx"])
        html = self._capture(authed_client, session)
        assert "Technology Stack" in html
        assert "Nginx" in html
        assert "PHP" in html
        assert "WordPress" in html
        # Deduped case-insensitively → 3 distinct (Nginx, PHP, WordPress).
        assert "3 distinct" in html


@pytest.mark.django_db
class TestScanCoverageBlock:
    """The report renders a Scan Coverage block only when edge blocking was seen."""

    def _capture(self, authed_client, session):
        captured = {}

        def capture_html(html):
            captured["html"] = html
            return b"%PDF-1.7"

        with patch("apps.core.console.reports.views._render_pdf", side_effect=capture_html):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")
        assert res.status_code == 200
        return captured["html"]

    def test_absent_when_no_blocking(self, authed_client, session, findings):
        html = self._capture(authed_client, session)
        assert "Scan Coverage" not in html

    def test_present_when_blocked(self, authed_client, session, findings):
        session.endpoints_probed = 41
        session.endpoints_blocked = 12
        session.waf_vendor = "cloudflare"
        session.save(update_fields=["endpoints_probed", "endpoints_blocked", "waf_vendor"])
        html = self._capture(authed_client, session)
        assert "Scan Coverage" in html
        assert "12 of 41 probed endpoints" in html
        assert "fingerprint suggests Cloudflare" in html


class TestPdfSeverityCounts:
    """Regression: the severity summary must count EVERY finding, not collapse
    to one per severity. The findings queryset is ordered by
    (severity, -discovered_at); that trailing sort field must not leak into the
    GROUP BY of the per-severity Count(), or every bucket collapses to 1."""

    def test_counts_all_findings_per_severity(self, authed_client, session):
        from apps.core.data.findings.models import Finding
        for sev, n in [("critical", 2), ("high", 3)]:
            for i in range(n):
                Finding.objects.create(
                    session=session, source="tls_checker", check_type="x",
                    severity=sev, title=f"{sev}-{i}", target="report.example.com",
                    description="d", remediation="f", status="open",
                )
        captured = {}

        def capture_html(html):
            captured["html"] = html
            return b"%PDF-1.7"

        with patch("apps.core.console.reports.views._render_pdf", side_effect=capture_html):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert res.status_code == 200
        html = captured["html"]
        # Correct counts — would render 1/1/2 under the GROUP BY leak bug.
        assert '<div class="n c-critical">2</div>' in html
        assert '<div class="n c-high">3</div>' in html
        assert '<div class="n">5</div>' in html

    def test_headline_tiles_show_unique_not_raw(self, authed_client, session):
        """Tiles + risk reflect consolidated unique issues, not raw detections;
        the raw count appears only in the consolidation note."""
        from apps.core.data.findings.models import Finding
        for ip in ("1.1.1.1:443", "2.2.2.2:443", "3.3.3.3:443"):
            Finding.objects.create(
                session=session, source="tls_checker", check_type="unencrypted_service",
                severity="critical", title=f"Unencrypted HTTPS on {ip}", target=ip,
                description="d", remediation="r", status="open",
            )
        captured = {}

        def capture_html(html):
            captured["html"] = html
            return b"%PDF-1.7"

        with patch("apps.core.console.reports.views._render_pdf", side_effect=capture_html):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert res.status_code == 200
        html = captured["html"]
        # 3 raw detections consolidate to 1 unique critical issue.
        assert '<div class="n c-critical">1</div>' in html
        assert '<div class="n">1</div>' in html  # total tile = unique
        assert "3 raw scanner detections into 1 unique issue" in html


@pytest.mark.django_db
class TestPartialScanDiagnostics:
    """A 'partial' scan shows a step-diagnostics table explaining which pipeline
    steps failed; a completed scan shows nothing."""

    def _render(self, authed_client, session):
        captured = {}

        def cap(html):
            captured["html"] = html
            return b"%PDF-1.7"

        with patch("apps.core.console.reports.views._render_pdf", side_effect=cap):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")
        assert res.status_code == 200
        return captured["html"]

    def test_diagnostics_shown_for_partial_scan(self, authed_client, session):
        from apps.core.engine.workflows.models import Workflow, WorkflowRun, WorkflowStepResult
        session.status = "partial"
        session.save(update_fields=["status"])
        wf = Workflow.objects.create(name="WF", is_default=False)
        run = WorkflowRun.objects.create(session=session, workflow=wf, status="partial")
        WorkflowStepResult.objects.create(run=run, tool="nuclei", status="failed",
                                          order=1, error="timed out after 1800s")
        WorkflowStepResult.objects.create(run=run, tool="httpx", status="completed", order=2)
        html = self._render(authed_client, session)
        assert "Scan Step Diagnostics" in html
        assert "nuclei" in html
        assert "timed out after 1800s" in html

    def test_no_diagnostics_for_completed_scan(self, authed_client, session):
        html = self._render(authed_client, session)  # session fixture is 'completed'
        assert "Scan Step Diagnostics" not in html


class TestTopRisksAndIntel:
    """The 'Fix First' block ranks by priority (KEV dominates) and the report
    surfaces EPSS/KEV threat intel collected by cve_intel."""

    def _mk(self, session, **kw):
        from apps.core.data.findings.models import Finding
        base = dict(
            session=session, source="tls_checker", check_type="unencrypted_service",
            severity="critical", target="1.1.1.1:5432", description="d", remediation="r",
            status="open", title="Unencrypted POSTGRESQL", extra={},
        )
        base.update(kw)
        return Finding.objects.create(**base)

    def _groups(self, session):
        from apps.core.console.reports.views import _group_findings_by_issue
        from apps.core.data.findings.models import Finding
        return _group_findings_by_issue(Finding.objects.filter(session=session))

    def test_epss_kev_rollup_onto_group(self, db, session):
        self._mk(session, source="nmap", check_type="cve", title="OpenSSL CVE",
                 extra={"cisa_kev": True, "epss_percentile": 0.97})
        grp = self._groups(session)[0]
        assert grp["cisa_kev"] is True
        assert grp["epss_percentile"] == 0.97

    def test_kev_outranks_non_kev_critical(self, db, session):
        from apps.core.console.reports.views import _top_risks
        self._mk(session, title="Plain critical", extra={})
        self._mk(session, source="nmap", check_type="cve", severity="medium",
                 title="Exploited medium", target="2.2.2.2:80",
                 extra={"cisa_kev": True, "epss_percentile": 0.99})
        top = _top_risks(self._groups(session))
        assert top[0]["title"] == "Exploited medium"  # KEV dominates severity
        assert top[0]["impact"]  # plain-language line attached

    def test_top_risks_excludes_low_medium_noise(self, db, session):
        from apps.core.console.reports.views import _top_risks
        self._mk(session, title="Crit", extra={})
        self._mk(session, severity="low", check_type="missing_referrer_policy",
                 title="Low thing", target="x", extra={})
        titles = [g["title"] for g in _top_risks(self._groups(session))]
        assert "Crit" in titles
        assert "Low thing" not in titles  # low/medium without KEV are not "fix first"

    def test_business_impact_on_high_crit_only(self, db, session):
        self._mk(session, title="Crit")  # unencrypted_service critical
        self._mk(session, severity="low", check_type="missing_referrer_policy",
                 title="Low thing", target="x")
        by_sev = {g["severity"]: g for g in self._groups(session)}
        assert by_sev["critical"]["business_impact"]        # populated
        assert by_sev["low"]["business_impact"] == ""       # not on low

    def test_email_control_business_impact_renders(self, db, session):
        # Email findings all share check_type="email"; the per-control impact copy
        # is keyed on extra["control"] and must render even at medium severity.
        self._mk(session, source="domain_security", check_type="email", severity="medium",
                 title="DMARC policy is none (monitoring only)", target="ex.com",
                 extra={"control": "dmarc"})
        grp = self._groups(session)[0]
        assert "email that appears to come from your domain" in grp["business_impact"]

    def test_rdap_lock_finding_has_no_expiry_line(self, db, session):
        # The transfer/delete/update lock findings share check_type="rdap" with
        # expiry findings — the expiry business-impact line must not render on them.
        self._mk(session, source="domain_security", check_type="rdap", severity="medium",
                 title="Domain transfer lock not enabled", target="ex.com",
                 extra={"statuses": []})
        grp = self._groups(session)[0]
        assert "expiry" not in grp["business_impact"].lower()
        assert grp["business_impact"] == ""   # medium + no specific copy → empty

    def test_report_renders_headline_and_snapshot(self, authed_client, session):
        self._mk(session, title="Unencrypted POSTGRESQL")
        captured = {}

        def cap(html):
            captured["html"] = html
            return b"%PDF-1.7"

        with patch("apps.core.console.reports.views._render_pdf", side_effect=cap):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")
        assert res.status_code == 200
        assert "Most urgent:" in captured["html"]                 # headline risk
        assert "point-in-time snapshot" in captured["html"]        # snapshot framing
        assert "Business Impact" in captured["html"]               # buyer-language on card

    def test_report_renders_fix_first_and_kev_badge(self, authed_client, session):
        self._mk(session, source="nmap", check_type="cve", title="Exploited CVE",
                 extra={"cisa_kev": True, "epss_percentile": 0.98})
        captured = {}

        def cap(html):
            captured["html"] = html
            return b"%PDF-1.7"

        with patch("apps.core.console.reports.views._render_pdf", side_effect=cap):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")
        assert res.status_code == 200
        assert "Priority Actions" in captured["html"]

    def test_hidden_findings_absent_from_pdf(self, authed_client, session):
        self._mk(session, source="domain_security", check_type="email", severity="info",
                 title="BIMI not configured", target="ex.com")
        self._mk(session, title="Unencrypted POSTGRESQL")  # a normal finding
        captured = {}
        with patch("apps.core.console.reports.views._render_pdf",
                   side_effect=lambda h: captured.update(html=h) or b"%PDF-1.7"):
            authed_client.get(f"/reports/{session.uuid}/pdf/")
        assert "BIMI not configured" not in captured["html"]
        assert "Unencrypted POSTGRESQL" in captured["html"]

    def test_rdap_failure_becomes_coverage_note(self, authed_client, session):
        self._mk(session, source="domain_security", check_type="rdap", severity="info",
                 title="RDAP lookup failed", target="ex.com")
        captured = {}
        with patch("apps.core.console.reports.views._render_pdf",
                   side_effect=lambda h: captured.update(html=h) or b"%PDF-1.7"):
            authed_client.get(f"/reports/{session.uuid}/pdf/")
        assert "Registration Data Unavailable" in captured["html"]  # coverage caveat
        assert "RDAP lookup failed" not in captured["html"]          # not a finding row

    def test_unconfigured_tools_hidden_from_methodology(self, authed_client, session):
        # github_secrets / dns_history no-op without a key/URL — the report must not
        # list them as coverage (would imply an assessment that didn't happen).
        self._mk(session, title="Unencrypted POSTGRESQL")
        captured = {}
        with patch("apps.core.console.credentials.resolver.get_credential", return_value=""), \
             patch("apps.core.console.reports.views._render_pdf",
                   side_effect=lambda h: captured.update(html=h) or b"%PDF-1.7"):
            authed_client.get(f"/reports/{session.uuid}/pdf/")
        assert "Historical DNS Records" not in captured["html"]   # dns_history hidden
        assert "GitHub Secret Exposure" not in captured["html"]   # github_secrets hidden
        assert "KEV" in captured["html"]


@pytest.mark.django_db
class TestFindingGrouping:
    """Repeated issues (identical write-up across targets) collapse into one
    block with a table of affected targets, instead of one full card each."""

    def _mk(self, session, **kw):
        from apps.core.data.findings.models import Finding
        base = dict(
            session=session, source="tls_checker", check_type="unencrypted_service",
            severity="critical", target="1.1.1.1:443", description="Plaintext service.",
            remediation="Enable TLS.", status="open", title="Unencrypted HTTPS on 1.1.1.1:443",
        )
        base.update(kw)
        return Finding.objects.create(**base)

    def test_endpoints_capped_at_50_with_overflow(self, db, session):
        """A finding firing on thousands of targets caps shown endpoints at 50
        (OOM guard) and records the overflow count for the 'N more' note."""
        from apps.core.console.reports.views import _group_findings_by_issue
        from apps.core.data.findings.models import Finding
        for i in range(120):
            self._mk(session, target=f"10.0.0.{i}:443",
                     title=f"Unencrypted HTTPS on 10.0.0.{i}:443")
        findings = Finding.objects.filter(session=session)
        grp = _group_findings_by_issue(findings)[0]
        shown = sum(len(row) for row in grp["endpoint_rows"])
        assert shown == 50
        assert grp["endpoint_overflow"] == 70

    def test_identical_writeups_collapse_and_strip_target(self, db, session):
        from apps.core.console.reports.views import _group_findings_by_issue
        from apps.core.data.findings.models import Finding
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

        def capture_html(html):
            captured["html"] = html
            return b"%PDF-1.7"

        with patch("apps.core.console.reports.views._render_pdf", side_effect=capture_html):
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
        from apps.core.console.reports.views import _risk_rating
        assert _risk_rating({"critical": 2, "high": 1}) == "CRITICAL"
        assert _risk_rating({"critical": 0, "high": 3, "medium": 1}) == "HIGH"
        assert _risk_rating({"medium": 4}) == "MEDIUM"
        assert _risk_rating({"low": 1}) == "LOW"
        assert _risk_rating({"critical": 0, "high": 0}) == "INFORMATIONAL"

    def test_finding_scope_check_type_overrides_source(self):
        from apps.core.console.reports.views import _finding_scope
        assert _finding_scope("domain_security", "rdap") == "Domain"       # check_type wins
        assert _finding_scope("domain_security", "dmarc") == "Email / DNS"  # source fallback
        assert _finding_scope("tls_checker", "san_mismatch") == "TLS / HTTPS"
        assert _finding_scope("mystery", "unknown") == "General"

    def test_group_carries_id_scope_cwe_cvss_cves(self, db, session):
        from apps.core.console.reports.views import _group_findings_by_issue
        from apps.core.data.findings.models import Finding
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
        from apps.core.data.findings.models import Finding
        for ip in ("1.1.1.1:443", "2.2.2.2:443"):
            Finding.objects.create(
                session=session, source="tls_checker", check_type="san_mismatch",
                severity="high", title=f"SAN mismatch on {ip}", target=ip,
                description="d", remediation="r", status="open",
            )
        captured = {}

        def capture_html(html):
            captured["html"] = html
            return b"%PDF-1.7"

        with patch("apps.core.console.reports.views._render_pdf", side_effect=capture_html):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")

        assert res.status_code == 200
        html = captured["html"]
        assert "Scope &amp; Methodology" in html
        assert "Network Exposure" in html          # a registry phase group
        assert 'class="ep-cell"' in html           # endpoints render as a pill grid


# ---------------------------------------------------------------------------
# CWE mapping guard — every emitted check_type must have an entry
# ---------------------------------------------------------------------------

import re
from pathlib import Path


def _emitted_check_types() -> set:
    """Collect every check_type string value emitted across all tool apps.

    Two sources:
    - Literal check_type="..." assignments (covers most tools)
    - _HEADER_CHECKS tuple table in web_checker (check_type passed via variable)
    """
    literal = re.compile(r'check_type=["\']([^"\']+)["\']')
    apps_dir = Path(__file__).parents[2] / "apps"

    found = set()
    for py_file in apps_dir.rglob("*.py"):
        if "test" in py_file.name:
            continue
        src = py_file.read_text(encoding="utf-8", errors="ignore")
        found.update(literal.findall(src))

    from apps.web_checker.analyzer import _HEADER_CHECKS
    found.update(row[1] for row in _HEADER_CHECKS)

    return found


def test_every_emitted_check_type_has_cwe_mapping():
    from apps.core.console.reports.views import _CWE_BY_CHECK

    unmapped = _emitted_check_types() - set(_CWE_BY_CHECK)
    assert not unmapped, (
        f"check_types with no CWE mapping in _CWE_BY_CHECK: {sorted(unmapped)}\n"
        "Add an entry in apps/core/console/reports/views.py for each."
    )


# ---------------------------------------------------------------------------
# The Five Questions (CEO-question executive framing)
# ---------------------------------------------------------------------------

class TestCeoQuestions:
    def _g(self, source, check_type, severity="high", n=1):
        return {"source": source, "check_type": check_type,
                "severity": severity, "instances": [object()] * n}

    def _by_q(self, groups, active):
        from apps.core.console.reports.views import _ceo_questions
        return {q["question"]: q for q in _ceo_questions(groups, active)}

    def test_email_finding_maps_to_spoof_question(self):
        qs = self._by_q([self._g("domain_security", "email")], {"domain_security"})
        assert qs["Can someone spoof our email?"]["status"] == "at_risk"

    def test_dnssec_rdap_maps_to_lose_domain(self):
        qs = self._by_q([self._g("domain_security", "dnssec", "medium")], {"domain_security"})
        assert qs["Can we lose our domain?"]["status"] == "attention"

    def test_typosquat_maps_to_impersonation(self):
        qs = self._by_q([self._g("typosquat", "lookalike_domain", "medium")], {"typosquat"})
        assert qs["Is anyone impersonating us?"]["status"] == "attention"

    def test_tool_not_run_is_not_checked(self):
        # No breach tools in the scan → honest "not checked", not a false all-clear.
        qs = self._by_q([], set())
        assert qs["Are staff logins stolen?"]["status"] == "not_checked"

    def test_tool_ran_no_findings_is_clear(self):
        qs = self._by_q([], {"breach_check"})
        assert qs["Are staff logins stolen?"]["status"] == "clear"

    def test_all_five_questions_present(self):
        qs = self._by_q([], {"domain_security"})
        assert len(qs) == 5


# ---------------------------------------------------------------------------
# AI Analyst Summary block (apps/core/console/ai integration)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAnalystSummaryBlock:
    def _capture_pdf_html(self, authed_client, session):
        captured = {}

        def capture_html(html):
            captured["html"] = html
            return b"%PDF-1.7"

        with patch("apps.core.console.reports.views._render_pdf", side_effect=capture_html):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")
        assert res.status_code == 200
        return captured["html"]

    def test_absent_without_ai_rows(self, authed_client, session, findings):
        html = self._capture_pdf_html(authed_client, session)
        assert "Analyst Summary" not in html
        assert "Cloudflare Workers AI" not in html

    def test_renders_summary_and_top_items(self, authed_client, session, findings):
        from apps.core.console.ai.models import AISummary, AITriage
        triage = AITriage.objects.create(
            session=session, status="completed", model="@cf/meta/test-model",
            overview="triage overview",
        )
        triage.items.create(
            finding=findings[0], finding_key="tls_checker:tls_expiry:TLS expired",
            rank=1, priority="fix_now", rationale="cert already expired",
        )
        AISummary.objects.create(
            session=session, kind="report", text="Exec summary paragraph.",
            model="@cf/meta/test-model",
        )
        html = self._capture_pdf_html(authed_client, session)
        assert "Analyst Summary" in html
        assert "Exec summary paragraph." in html
        assert "TLS expired" in html
        assert "cert already expired" in html
        assert "@cf/meta/test-model" in html
        assert "review before acting" in html

    def test_triage_overview_fallback_when_no_report_summary(self, authed_client, session, findings):
        from apps.core.console.ai.models import AITriage
        AITriage.objects.create(
            session=session, status="completed", model="m", overview="fallback overview",
        )
        html = self._capture_pdf_html(authed_client, session)
        assert "Analyst Summary" in html
        assert "fallback overview" in html

    def test_failed_triage_renders_nothing(self, authed_client, session, findings):
        from apps.core.console.ai.models import AITriage
        AITriage.objects.create(session=session, status="failed", overview="stale")
        html = self._capture_pdf_html(authed_client, session)
        assert "Analyst Summary" not in html

    def test_ai_context_helper_never_raises(self, session):
        from apps.core.console.reports.views import _ai_context
        with patch("apps.core.console.ai.models.AITriage.objects") as broken:
            broken.filter.side_effect = RuntimeError("db broke")
            assert _ai_context(session) == {}


# ---------------------------------------------------------------------------
# "Since Your Last Scan" delta block
# ---------------------------------------------------------------------------

class TestSinceLastScanBlock:
    """The report shows what changed versus the previous scan of the same domain:
    new / resolved / still-open findings. Absent on the first scan (no baseline),
    and the diff ignores subscans (they run only a subset of tools) and respects
    the report's min_severity filter + hidden-title suppression."""

    def _capture_pdf_html(self, authed_client, session, qs=""):
        captured = {}

        def capture_html(html):
            captured["html"] = html
            return b"%PDF-1.7"

        with patch("apps.core.console.reports.views._render_pdf", side_effect=capture_html):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/{qs}")
        assert res.status_code == 200
        return captured["html"]

    def _finding(self, session, title, severity, source, check_type, **kw):
        from apps.core.data.findings.models import Finding
        return Finding.objects.create(
            session=session, source=source, check_type=check_type,
            severity=severity, title=title, target="report.example.com",
            description="desc", remediation="fix", status="open", **kw,
        )

    def _prev_session(self, domain="report.example.com", scan_type="full"):
        from apps.core.engine.scans.models import ScanSession
        return ScanSession.objects.create(
            domain=domain, scan_type=scan_type, status="completed",
            start_time=timezone.now() - timezone.timedelta(days=7),
            end_time=timezone.now() - timezone.timedelta(days=7),
        )

    def test_absent_on_first_scan(self, authed_client, session, findings):
        html = self._capture_pdf_html(authed_client, session)
        assert "Since Your Last Scan" not in html

    def test_new_and_resolved_and_still_open(self, authed_client, session):
        prev = self._prev_session()
        # previous: A (shared) + B (will be resolved)
        self._finding(prev, "Shared issue", "high", "tls_checker", "tls_expiry")
        self._finding(prev, "Resolved issue", "medium", "domain_security", "dmarc")
        # current: A (shared, still open) + C (new)
        self._finding(session, "Shared issue", "high", "tls_checker", "tls_expiry")
        self._finding(session, "New issue", "critical", "nuclei", "cve")

        html = self._capture_pdf_html(authed_client, session)
        assert "Since Your Last Scan" in html
        assert "1 new" in html
        assert "1 resolved" in html
        assert "1 still open" in html
        assert "New issue" in html       # listed under "New this scan"
        assert "Resolved issue" in html  # listed under "Resolved"

    def test_from_helper_directly(self, db, session):
        from apps.core.console.reports.views import _since_last_scan
        prev = self._prev_session()
        self._finding(prev, "Old one", "low", "web_checker", "cors")
        self._finding(session, "Old one", "low", "web_checker", "cors")
        self._finding(session, "Brand new", "high", "nmap", "cve")
        result = _since_last_scan(session, ["critical", "high", "medium", "low", "info"])
        assert result["new_count"] == 1
        assert result["resolved_count"] == 0
        assert result["still_open"] == 1
        assert result["new"][0]["title"] == "Brand new"

    def test_subscan_is_not_a_baseline(self, authed_client, session):
        # A subscan of the same domain must not be chosen as the baseline, even if
        # it's the most recent — it runs only a subset of tools.
        sub = self._prev_session()
        sub.scan_type = "subscan"
        sub.start_time = timezone.now() - timezone.timedelta(hours=1)
        sub.save()
        self._finding(sub, "Subscan-only", "high", "nuclei", "cve")
        self._finding(session, "Current", "high", "tls_checker", "tls_expiry")
        html = self._capture_pdf_html(authed_client, session)
        # No non-subscan prior scan exists → treated as the baseline (block absent).
        assert "Since Your Last Scan" not in html

    def test_respects_min_severity_filter(self, authed_client, session):
        prev = self._prev_session()
        self._finding(prev, "Shared high", "high", "tls_checker", "tls_expiry")
        self._finding(session, "Shared high", "high", "tls_checker", "tls_expiry")
        # A new LOW finding should be invisible when min_severity=high.
        self._finding(session, "New low", "low", "web_checker", "cors")
        html = self._capture_pdf_html(authed_client, session, qs="?min_severity=high")
        assert "Since Your Last Scan" in html
        assert "New low" not in html
        assert "0 new" in html

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


# ---------------------------------------------------------------------------
# Per-finding "Recommended Next Steps" (hosted reports only)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestNextStepsBlock:
    """Concrete remediation checklists render in the PDF finding detail ONLY on
    hosted reports (REPORT_CTA_URL configured). Self-hosters keep the Remediation
    prose but not the numbered checklist. The mapping is keyed by effective key."""

    def _capture(self, authed_client, session):
        captured = {}

        def capture_html(html):
            captured["html"] = html
            return b"%PDF-1.7"

        with patch("apps.core.console.reports.views._render_pdf", side_effect=capture_html):
            res = authed_client.get(f"/reports/{session.uuid}/pdf/")
        assert res.status_code == 200
        return captured["html"]

    def test_absent_when_not_hosted(self, authed_client, session, findings, settings):
        settings.REPORT_CTA_URL = ""
        html = self._capture(authed_client, session)
        assert "Recommended Next Steps" not in html

    def test_present_when_hosted(self, authed_client, session, findings, settings):
        settings.REPORT_CTA_URL = "https://example.com/help"
        settings.REPORT_CTA_TEXT = "Need help?"
        html = self._capture(authed_client, session)
        assert "Recommended Next Steps" in html
        # The DMARC finding in the fixture maps to a concrete step.
        assert "Publish" in html and "_dmarc" in html

    def test_group_attaches_next_steps_for_mapped_check(self, db, session):
        from apps.core.console.reports.views import _group_findings_by_issue
        from apps.core.data.findings.models import Finding
        f = Finding.objects.create(
            session=session, source="web_checker", check_type="missing_hsts",
            severity="medium", title="Missing Strict-Transport-Security on https://x",
            description="d", remediation="r", target="https://x",
        )
        groups = _group_findings_by_issue([f])
        assert groups[0]["next_steps"]  # non-empty
        assert any("Strict-Transport-Security" in s for s in groups[0]["next_steps"])

    def test_group_empty_next_steps_for_unmapped_check(self, db, session):
        from apps.core.console.reports.views import _group_findings_by_issue
        from apps.core.data.findings.models import Finding
        f = Finding.objects.create(
            session=session, source="some_tool", check_type="totally_unmapped_check",
            severity="low", title="Odd thing", description="d", remediation="r",
            target="x",
        )
        groups = _group_findings_by_issue([f])
        assert groups[0]["next_steps"] == []

    def test_email_control_keys_next_steps(self, db, session):
        # Email findings share check_type="email"; next steps resolve via control.
        from apps.core.console.reports.views import _group_findings_by_issue
        from apps.core.data.findings.models import Finding
        f = Finding.objects.create(
            session=session, source="domain_security", check_type="email",
            severity="medium", title="SPF record missing on example.com",
            description="d", remediation="r", target="example.com",
            extra={"control": "spf"},
        )
        groups = _group_findings_by_issue([f])
        assert any("SPF" in s for s in groups[0]["next_steps"])
