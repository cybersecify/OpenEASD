"""Unit tests for apps/hudson_rock — collector, analyzer, scanner.

Hudson Rock's Cavalier API is mocked throughout; no real network. The privacy
invariant (never persist plaintext credentials / individual emails) is asserted
against a synthetic response that deliberately embeds a fake password + email.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from apps.hudson_rock import collector
from apps.hudson_rock.analyzer import analyze
from apps.hudson_rock.collector import collect


def _resp(status=200, json_data=None, headers=None, raise_json=False):
    m = MagicMock()
    m.status_code = status
    m.headers = headers or {}
    if raise_json:
        m.json.side_effect = ValueError("no json")
    else:
        m.json.return_value = json_data if json_data is not None else {}
    return m


_COUNTS = {
    "employees": 3,
    "users": 12,
    "third_parties": 1,
    "total": 16,
    "totalStealers": 9,
    "stealerFamilies": {"RedLine": 5, "Raccoon": 3, "Vidar": 1},
    "last_employee_compromised": "2025-11-02",
    "last_user_compromised": "2026-01-20",
}

_URLS = {"data": [{"url": "https://login.example.com"}, {"url": "https://vpn.example.com"}]}


# ---------------------------------------------------------------------------
# Collector — hits both endpoints, keyless, honest UA
# ---------------------------------------------------------------------------

class TestCollect:
    def test_hits_both_endpoints_keyless_with_ua(self):
        calls = []

        def fake_get(url, params=None, headers=None, timeout=None):
            calls.append((url, params, headers, timeout))
            if "search-by-domain" in url.split("/"):
                return _resp(json_data=_COUNTS)
            return _resp(json_data=_URLS)

        with patch.object(collector.requests, "get", side_effect=fake_get):
            data = collect("example.com")

        # both endpoints called
        endpoints = [c[0] for c in calls]
        assert any("search-by-domain" in u for u in endpoints)
        assert any("urls-by-domain" in u for u in endpoints)
        # keyless: only the domain param, no api key
        for _url, params, headers, timeout in calls:
            assert params == {"domain": "example.com"}
            assert "key" not in params and "api_key" not in params
            # honest UA sent
            assert "OpenEASD" in headers["User-Agent"]
            assert timeout == 10
        assert data["counts"] == _COUNTS
        assert data["urls"] == _URLS

    def test_timeout_fails_graceful(self):
        with patch.object(collector.requests, "get", side_effect=requests.Timeout("slow")):
            data = collect("example.com")  # must not raise
        assert data == {"counts": {}, "urls": None}

    def test_http_500_fails_graceful(self):
        with patch.object(collector.requests, "get", return_value=_resp(status=500)):
            data = collect("example.com")
        assert data["counts"] == {}
        assert data["urls"] is None

    def test_bad_json_fails_graceful(self):
        with patch.object(collector.requests, "get", return_value=_resp(raise_json=True)):
            data = collect("example.com")
        assert data["counts"] == {}
        assert data["urls"] is None

    def test_429_exhausted_fails_graceful(self):
        resp = _resp(status=429, headers={"Retry-After": "1"})
        with patch.object(collector.requests, "get", return_value=resp), \
             patch.object(collector.time, "sleep") as mock_sleep:
            data = collect("example.com")
        assert data == {"counts": {}, "urls": None}
        assert mock_sleep.called  # backoff was honoured before giving up

    def test_429_then_success_retries(self):
        seq = {"search-by-domain": [_resp(status=429, headers={"Retry-After": "1"}),
                                    _resp(json_data=_COUNTS)],
               "urls-by-domain": [_resp(json_data=_URLS)]}

        def fake_get(url, params=None, headers=None, timeout=None):
            key = "search-by-domain" if "search-by-domain" in url.split("/") else "urls-by-domain"
            return seq[key].pop(0)

        with patch.object(collector.requests, "get", side_effect=fake_get), \
             patch.object(collector.time, "sleep"):
            data = collect("example.com")
        assert data["counts"] == _COUNTS


# ---------------------------------------------------------------------------
# Analyzer — one Finding, severity, attribution, privacy
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAnalyze:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_no_finding_when_counts_zero(self):
        s = self._session()
        findings = analyze(s, "example.com", {"counts": {"employees": 0, "users": 0}, "urls": None})
        assert findings == []

    def test_no_finding_when_counts_missing(self):
        s = self._session()
        assert analyze(s, "example.com", {"counts": {}, "urls": None}) == []

    def test_high_severity_when_employees(self):
        s = self._session()
        findings = analyze(s, "example.com", {"counts": _COUNTS, "urls": _URLS})
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "high"
        assert f.source == "hudson_rock"
        assert f.check_type == "infostealer_exposure"
        assert f.target == "example.com"

    def test_medium_severity_users_only(self):
        s = self._session()
        counts = dict(_COUNTS, employees=0, users=5)
        findings = analyze(s, "example.com", {"counts": counts, "urls": None})
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_finding_includes_counts_families_urls_attribution(self):
        s = self._session()
        f = analyze(s, "example.com", {"counts": _COUNTS, "urls": _URLS})[0]
        desc = f.description
        assert "3 employee" in f.title and "12 user" in f.title
        assert "RedLine" in desc  # top stealer family
        assert "2026-01-20" in desc  # most recent compromise
        assert "login.example.com" in desc  # affected URL
        assert "Hudson Rock (Cavalier)" in desc  # attribution
        assert "MFA" in f.remediation
        # extra structured data, no plaintext
        assert f.extra["employees"] == 3
        assert f.extra["users"] == 12
        assert "RedLine" in f.extra["stealer_families"]
        assert any(_u == "https://login.example.com" for _u in f.extra["affected_urls"])
        assert f.extra["last_compromised"] == "2026-01-20"

    def test_affected_urls_capped(self):
        s = self._session()
        many = {"data": [{"url": f"https://h{i}.example.com"} for i in range(30)]}
        f = analyze(s, "example.com", {"counts": _COUNTS, "urls": many})[0]
        assert len(f.extra["affected_urls"]) == 10

    def test_never_stores_plaintext_credentials_or_emails(self):
        """Privacy invariant: even if Cavalier returns per-person data with a
        password + email, none of it may appear in any Finding field."""
        s = self._session()
        poisoned_counts = dict(_COUNTS)
        # simulate a response that leaks per-person records
        poisoned_counts["data"] = [
            {
                "email": "victim@example.com",
                "password": "SuperSecret123!",
                "employee": True,
            }
        ]
        poisoned_urls = {
            "data": [
                {
                    "url": "https://login.example.com",
                    "password": "SuperSecret123!",
                    "email": "victim@example.com",
                }
            ]
        }
        f = analyze(s, "example.com", {"counts": poisoned_counts, "urls": poisoned_urls})[0]

        haystack = " ".join([
            f.title, f.description, f.remediation, f.target, str(f.extra),
        ])
        assert "SuperSecret123!" not in haystack
        assert "victim@example.com" not in haystack
        # the system-level URL is still surfaced (that's allowed)
        assert any(_u == "https://login.example.com" for _u in f.extra["affected_urls"])

    def test_handles_bare_string_url_list(self):
        s = self._session()
        f = analyze(s, "example.com", {
            "counts": _COUNTS,
            "urls": ["https://login.example.com", "https://vpn.example.com"],
        })[0]
        assert any(_u == "https://login.example.com" for _u in f.extra["affected_urls"])


# ---------------------------------------------------------------------------
# Scanner — orchestration + persistence
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestScanner:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_saves_finding(self):
        from apps.hudson_rock.scanner import run_hudson_rock
        from apps.core.findings.models import Finding
        s = self._session()
        with patch("apps.hudson_rock.scanner.collect",
                   return_value={"counts": _COUNTS, "urls": _URLS}):
            saved = run_hudson_rock(s)
        assert len(saved) == 1
        assert Finding.objects.filter(session=s, source="hudson_rock").count() == 1

    def test_no_exposure_saves_nothing(self):
        from apps.hudson_rock.scanner import run_hudson_rock
        from apps.core.findings.models import Finding
        s = self._session()
        with patch("apps.hudson_rock.scanner.collect",
                   return_value={"counts": {"employees": 0, "users": 0}, "urls": None}):
            saved = run_hudson_rock(s)
        assert saved == []
        assert Finding.objects.filter(session=s).count() == 0

    def test_collector_exception_never_fails_scan(self):
        from apps.hudson_rock.scanner import run_hudson_rock
        s = self._session()
        with patch("apps.hudson_rock.scanner.collect", side_effect=RuntimeError("boom")):
            saved = run_hudson_rock(s)  # must not raise
        assert saved == []


# ---------------------------------------------------------------------------
# End-to-end contract — realistic Cavalier body through real collect → analyze
# (only requests.get is mocked)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestCollectAnalyzeContract:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_realistic_body_produces_saved_finding(self):
        """Feed a realistic two-endpoint Cavalier response through the real
        collect() and analyze() (via run_hudson_rock) — only requests.get is
        mocked — and assert a single aggregate infostealer Finding is persisted
        with the expected counts, families and attribution."""
        from apps.hudson_rock.scanner import run_hudson_rock
        from apps.core.findings.models import Finding

        def fake_get(url, params=None, headers=None, timeout=None):
            if "search-by-domain" in url.split("/"):
                return _resp(json_data=_COUNTS)
            return _resp(json_data=_URLS)

        s = self._session()
        with patch.object(collector.requests, "get", side_effect=fake_get):
            saved = run_hudson_rock(s)

        assert len(saved) == 1
        f = Finding.objects.get(session=s, source="hudson_rock")
        assert f.check_type == "infostealer_exposure"
        assert f.severity == "high"          # 3 employees exposed
        assert f.extra["employees"] == 3
        assert f.extra["users"] == 12
        assert "RedLine" in f.extra["stealer_families"]
        assert any(_u == "https://login.example.com" for _u in f.extra["affected_urls"])
        assert "Hudson Rock (Cavalier)" in f.description
        # privacy invariant still holds end-to-end: no raw creds anywhere
        assert "password" not in str(f.extra).lower()
