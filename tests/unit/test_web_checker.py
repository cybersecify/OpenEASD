"""Unit tests for apps/web_checker — collector response parsing, analyzer findings."""

from unittest.mock import MagicMock, patch

import pytest

from apps.web_checker.collector import _parse_cookies, _extract_title, _parse_samesite, collect
from apps.web_checker.analyzer import analyze
from apps.web_checker.scanner import run_web_check


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(url_fk=None, port_fk=None, url="https://example.com",
                 host="example.com", status_code=200,
                 headers=None, cookies=None, body_snippet="",
                 title="", cors_reflects_origin=False, error=None):
    return {
        "url": url, "url_fk": url_fk, "port_fk": port_fk,
        "host": host, "status_code": status_code,
        "headers": headers if headers is not None else {},
        "cookies": cookies if cookies is not None else [],
        "body_snippet": body_snippet, "title": title,
        "cors_reflects_origin": cors_reflects_origin,
        "error": error,
    }


# ---------------------------------------------------------------------------
# Unit tests — no DB needed
# ---------------------------------------------------------------------------

class TestParseCookies:
    def test_secure_and_httponly_detected(self):
        resp = MagicMock()
        resp.raw.headers.getlist.return_value = [
            "session=abc123; Secure; HttpOnly; SameSite=Strict"
        ]
        resp.cookies = []
        cookies = _parse_cookies(resp)
        assert len(cookies) == 1
        assert cookies[0]["name"] == "session"
        assert cookies[0]["secure"] is True
        assert cookies[0]["httponly"] is True
        assert cookies[0]["samesite"] == "Strict"

    def test_missing_flags(self):
        resp = MagicMock()
        resp.raw.headers.getlist.return_value = [
            "token=xyz; Path=/"
        ]
        resp.cookies = []
        cookies = _parse_cookies(resp)
        assert cookies[0]["secure"] is False
        assert cookies[0]["httponly"] is False
        assert cookies[0]["samesite"] is None

    def test_multiple_cookies(self):
        resp = MagicMock()
        resp.raw.headers.getlist.return_value = [
            "a=1; Secure", "b=2; HttpOnly"
        ]
        resp.cookies = []
        cookies = _parse_cookies(resp)
        assert len(cookies) == 2


class TestParseSamesite:
    def test_lax(self):
        assert _parse_samesite("; samesite=lax; path=/") == "Lax"

    def test_strict(self):
        assert _parse_samesite("; samesite=strict") == "Strict"

    def test_none(self):
        assert _parse_samesite("; samesite=none; secure") == "None"

    def test_missing(self):
        assert _parse_samesite("; path=/; httponly") is None


class TestExtractTitle:
    def test_simple_title(self):
        assert _extract_title("<html><title>My Page</title></html>") == "My Page"

    def test_index_of(self):
        assert "Index of" in _extract_title("<title>Index of /uploads</title>")

    def test_no_title(self):
        assert _extract_title("<html><body>Hello</body></html>") == ""


# ---------------------------------------------------------------------------
# Analyzer — DB required
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestWebCheckerHeaders:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=443, protocol="tcp", state="open", service="https", source="naabu")
        return sess, p

    def test_missing_csp_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk, headers={})]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "missing_csp"), None)
        assert f is not None and f.severity == "high"

    def test_missing_xfo_medium(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk, headers={})]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "missing_xfo"), None)
        assert f is not None and f.severity == "medium"

    def test_missing_xcto_medium(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk, headers={})]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "missing_xcto"), None)
        assert f is not None and f.severity == "medium"

    def test_all_headers_present_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk, headers={
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Permissions-Policy": "camera=()",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        })]
        findings = analyze(sess, results)
        header_types = {"missing_csp", "missing_xfo", "missing_xcto",
                        "missing_permissions_policy", "missing_referrer_policy"}
        assert not any(f.check_type in header_types for f in findings)

    def test_error_result_skipped(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk, error="Connection refused")]
        findings = analyze(sess, results)
        assert len(findings) == 0


@pytest.mark.django_db
class TestWebCheckerCookies:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=443, protocol="tcp", state="open", service="https", source="naabu")
        return sess, p

    def test_missing_secure_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk,
                                cookies=[{"name": "sid", "secure": False, "httponly": True, "samesite": "Lax"}])]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "cookie_missing_secure"), None)
        assert f is not None and f.severity == "high"

    def test_missing_httponly_medium(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk,
                                cookies=[{"name": "sid", "secure": True, "httponly": False, "samesite": "Lax"}])]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "cookie_missing_httponly"), None)
        assert f is not None and f.severity == "medium"

    def test_missing_samesite_medium(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk,
                                cookies=[{"name": "sid", "secure": True, "httponly": True, "samesite": None}])]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "cookie_missing_samesite"), None)
        assert f is not None and f.severity == "medium"

    def test_all_flags_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk,
                                cookies=[{"name": "sid", "secure": True, "httponly": True, "samesite": "Strict"}])]
        findings = analyze(sess, results)
        cookie_types = {"cookie_missing_secure", "cookie_missing_httponly", "cookie_missing_samesite"}
        assert not any(f.check_type in cookie_types for f in findings)

    def test_http_no_secure_check(self):
        """Secure flag check is skipped for HTTP-only URLs."""
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk, url="http://example.com",
                                cookies=[{"name": "sid", "secure": False, "httponly": True, "samesite": "Lax"}])]
        findings = analyze(sess, results)
        assert not any(f.check_type == "cookie_missing_secure" for f in findings)


@pytest.mark.django_db
class TestWebCheckerCORS:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=443, protocol="tcp", state="open", service="https", source="naabu")
        return sess, p

    def test_cors_wildcard_credentials_critical(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk, headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        })]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "cors_wildcard_credentials"), None)
        assert f is not None and f.severity == "critical"

    def test_cors_origin_reflection_high(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk,
                                headers={"Access-Control-Allow-Origin": "https://evil.example.com"},
                                cors_reflects_origin=True)]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "cors_origin_reflection"), None)
        assert f is not None and f.severity == "high"

    def test_cors_wildcard_medium(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk,
                                headers={"Access-Control-Allow-Origin": "*"})]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "cors_wildcard"), None)
        assert f is not None and f.severity == "medium"

    def test_no_cors_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk, headers={})]
        findings = analyze(sess, results)
        cors_types = {"cors_wildcard_credentials", "cors_origin_reflection", "cors_wildcard"}
        assert not any(f.check_type in cors_types for f in findings)


@pytest.mark.django_db
class TestWebCheckerServerDisclosure:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=443, protocol="tcp", state="open", service="https", source="naabu")
        return sess, p

    def test_server_version_low(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk,
                                headers={"Server": "Apache/2.4.51 (Ubuntu)"})]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "server_version_disclosure"), None)
        assert f is not None and f.severity == "low"

    def test_server_no_version_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk,
                                headers={"Server": "nginx"})]
        findings = analyze(sess, results)
        assert not any(f.check_type == "server_version_disclosure" for f in findings)

    def test_powered_by_low(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk,
                                headers={"X-Powered-By": "Express"})]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "server_poweredby_disclosure"), None)
        assert f is not None and f.severity == "low"


@pytest.mark.django_db
class TestWebCheckerDirectoryListing:
    def _make_port(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        p = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                port=443, protocol="tcp", state="open", service="https", source="naabu")
        return sess, p

    def test_directory_listing_medium(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk, title="Index of /uploads")]
        findings = analyze(sess, results)
        f = next((f for f in findings if f.check_type == "directory_listing"), None)
        assert f is not None and f.severity == "medium"

    def test_normal_page_no_finding(self):
        sess, port_fk = self._make_port()
        results = [_make_result(port_fk=port_fk, title="Welcome to My Site")]
        findings = analyze(sess, results)
        assert not any(f.check_type == "directory_listing" for f in findings)


# ---------------------------------------------------------------------------
# Collector — mocked requests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestWebCheckerCollector:
    def _make_session(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain, IPAddress, Port
        from apps.core.web_assets.models import URL
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        port = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4",
                                   port=443, protocol="tcp", state="open", service="https", source="naabu")
        sub = Subdomain.objects.create(session=sess, domain="example.com",
                                       subdomain="www.example.com", source="subfinder")
        URL.objects.create(session=sess, subdomain=sub, port=port,
                           url="https://www.example.com:443",
                           host="www.example.com", port_number=443, scheme="https", source="httpx")
        return sess

    def test_successful_fetch(self):
        sess = self._make_session()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Server": "nginx", "Content-Type": "text/html"}
        mock_resp.text = "<html><title>Test</title></html>"
        mock_resp.raw.headers.getlist.return_value = []
        mock_resp.cookies = []

        with patch("apps.web_checker.collector.requests.get", return_value=mock_resp):
            results = collect(sess)

        assert len(results) == 1
        assert results[0]["status_code"] == 200
        assert results[0]["title"] == "Test"
        assert results[0]["error"] is None

    def test_connection_error(self):
        import requests as req
        sess = self._make_session()

        with patch("apps.web_checker.collector.requests.get",
                   side_effect=req.ConnectionError("refused")):
            results = collect(sess)

        assert len(results) == 1
        assert results[0]["error"] is not None

    def test_empty_session(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        results = collect(sess)
        assert results == []


# ---------------------------------------------------------------------------
# Scanner orchestrator
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestWebCheckerScanner:
    def test_scanner_creates_findings(self):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        fake_results = [_make_result(headers={})]  # Missing all headers

        with patch("apps.web_checker.scanner.collect", return_value=fake_results):
            findings = run_web_check(sess)

        assert len(findings) >= 5  # At least 5 missing header findings
        assert Finding.objects.filter(session=sess, source="web_checker").count() == len(findings)

    def test_scanner_empty_session(self):
        from apps.core.scans.models import ScanSession
        sess = ScanSession.objects.create(domain="empty.com", scan_type="full")
        with patch("apps.web_checker.scanner.collect", return_value=[]):
            findings = run_web_check(sess)
        assert findings == []
