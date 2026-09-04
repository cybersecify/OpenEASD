"""Unit tests for apps/breach_check — collector, analyzer, scanner.

Both breach APIs (XposedOrNot free catalog + Have I Been Pwned) are mocked
throughout; no real network. The privacy invariant (never persist plaintext
credentials / individual email addresses / email aliases) is asserted against
synthetic responses that deliberately embed fake per-account PII.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests
from django.test import override_settings

from apps.breach_check import collector
from apps.breach_check.analyzer import analyze
from apps.breach_check.collector import collect


def _resp(status=200, json_data=None, headers=None, raise_json=False):
    m = MagicMock()
    m.status_code = status
    m.headers = headers or {}
    if raise_json:
        m.json.side_effect = ValueError("no json")
    else:
        m.json.return_value = json_data if json_data is not None else {}
    return m


# XposedOrNot public-catalog body (no key). Public breach metadata only.
_XON_BODY = {
    "status": "success",
    "exposedBreaches": [
        {"breachID": "Adobe", "breachedDate": "2013-10-04", "exposedRecords": 152445165},
        {"breachID": "LinkedIn", "breachedDate": "2012-05-05", "exposedRecords": 164611595},
    ],
}

# HIBP breacheddomain body — alias -> [breach names]. The alias keys are email
# local-parts (PII) and must never survive into the result / a Finding.
_HIBP_BODY = {
    "jsmith": ["Adobe"],
    "adecker": ["Adobe", "LinkedIn", "Dropbox"],
    "root": ["Dropbox"],
}


# ---------------------------------------------------------------------------
# Collector — free XposedOrNot tier (no key)
# ---------------------------------------------------------------------------

class TestCollectXposedOrNot:
    @override_settings(HIBP_API_KEY="")
    def test_free_tier_parses_and_sends_honest_ua_no_key(self):
        calls = []

        def fake_get(url, headers=None, timeout=None):
            calls.append((url, headers, timeout))
            return _resp(json_data=_XON_BODY)

        with patch.object(collector.requests, "get", side_effect=fake_get):
            data = collect("example.com")

        assert len(calls) == 1
        url, headers, timeout = calls[0]
        assert "xposedornot.com" in url
        assert "breaches" in url and "domain=example.com" in url
        assert "hibp-api-key" not in headers  # keyless
        assert "OpenEASD" in headers["User-Agent"]  # honest UA
        assert timeout == 10

        assert data["tier"] == "xposedornot"
        assert data["accounts"] == 0  # catalog has no per-domain account count
        assert data["breach_count"] == 2
        names = {b["name"] for b in data["breaches"]}
        assert names == {"Adobe", "LinkedIn"}
        assert any(b["year"] == "2013" for b in data["breaches"])

    @override_settings(HIBP_API_KEY="")
    def test_empty_catalog_returns_zero(self):
        with patch.object(collector.requests, "get",
                          return_value=_resp(json_data={"status": "success", "exposedBreaches": []})):
            data = collect("example.com")
        assert data["breach_count"] == 0
        assert data["breaches"] == []

    @override_settings(HIBP_API_KEY="")
    def test_timeout_fails_graceful(self):
        with patch.object(collector.requests, "get", side_effect=requests.Timeout("slow")):
            data = collect("example.com")  # must not raise
        assert data["breach_count"] == 0

    @override_settings(HIBP_API_KEY="")
    def test_http_500_fails_graceful(self):
        with patch.object(collector.requests, "get", return_value=_resp(status=500)):
            data = collect("example.com")
        assert data["breach_count"] == 0

    @override_settings(HIBP_API_KEY="")
    def test_bad_json_fails_graceful(self):
        with patch.object(collector.requests, "get", return_value=_resp(raise_json=True)):
            data = collect("example.com")
        assert data["breach_count"] == 0

    @override_settings(HIBP_API_KEY="")
    def test_429_exhausted_fails_graceful(self):
        resp = _resp(status=429, headers={"Retry-After": "1"})
        with patch.object(collector.requests, "get", return_value=resp), \
             patch.object(collector.time, "sleep") as mock_sleep:
            data = collect("example.com")
        assert data["breach_count"] == 0
        assert mock_sleep.called  # backoff honoured before giving up

    @override_settings(HIBP_API_KEY="")
    def test_429_then_success_retries(self):
        seq = [_resp(status=429, headers={"Retry-After": "1"}), _resp(json_data=_XON_BODY)]
        with patch.object(collector.requests, "get", side_effect=lambda *a, **k: seq.pop(0)), \
             patch.object(collector.time, "sleep"):
            data = collect("example.com")
        assert data["breach_count"] == 2


# ---------------------------------------------------------------------------
# Collector — HIBP authoritative tier (key set) + PRIVACY
# ---------------------------------------------------------------------------

class TestCollectHIBP:
    @override_settings(HIBP_API_KEY="secret-key-123")
    def test_key_set_uses_hibp_with_header(self):
        calls = []

        def fake_get(url, headers=None, timeout=None):
            calls.append((url, headers))
            return _resp(json_data=_HIBP_BODY)

        with patch.object(collector.requests, "get", side_effect=fake_get):
            data = collect("example.com")

        assert len(calls) == 1
        url, headers = calls[0]
        assert "haveibeenpwned.com" in url
        assert "breacheddomain/example.com" in url
        assert headers["hibp-api-key"] == "secret-key-123"  # key sent as header
        assert "OpenEASD" in headers["User-Agent"]  # HIBP requires a UA

        assert data["tier"] == "hibp"
        assert data["accounts"] == 3  # three aliases -> three accounts
        assert data["breach_count"] == 3  # union: Adobe, LinkedIn, Dropbox
        assert {b["name"] for b in data["breaches"]} == {"Adobe", "LinkedIn", "Dropbox"}

    @override_settings(HIBP_API_KEY="secret-key-123")
    def test_hibp_never_returns_alias_keys(self):
        """PRIVACY: email-alias keys (PII) must never survive into the result."""
        with patch.object(collector.requests, "get", return_value=_resp(json_data=_HIBP_BODY)):
            data = collect("example.com")
        blob = str(data)
        for alias in ("jsmith", "adecker", "root"):
            assert alias not in blob

    @override_settings(HIBP_API_KEY="secret-key-123")
    def test_hibp_404_is_no_data_not_error(self):
        with patch.object(collector.requests, "get", return_value=_resp(status=404)):
            data = collect("example.com")
        assert data["tier"] == "hibp"
        assert data["breach_count"] == 0

    @override_settings(HIBP_API_KEY="secret-key-123")
    def test_hibp_403_unverified_domain_fails_graceful(self):
        with patch.object(collector.requests, "get", return_value=_resp(status=403)):
            data = collect("example.com")  # must not raise
        assert data["breach_count"] == 0

    @override_settings(HIBP_API_KEY="secret-key-123")
    def test_hibp_timeout_fails_graceful(self):
        with patch.object(collector.requests, "get", side_effect=requests.Timeout("slow")):
            data = collect("example.com")
        assert data["breach_count"] == 0


# ---------------------------------------------------------------------------
# Analyzer — one Finding, severity, attribution, privacy
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAnalyze:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_no_finding_when_zero(self):
        s = self._session()
        assert analyze(s, "example.com", {"tier": "xposedornot", "breach_count": 0, "breaches": []}) == []

    def test_no_finding_when_missing(self):
        s = self._session()
        assert analyze(s, "example.com", {}) == []

    def test_medium_severity_old_breaches_no_accounts(self):
        s = self._session()
        data = {
            "tier": "xposedornot", "accounts": 0, "breach_count": 2,
            "breaches": [{"name": "Adobe", "year": "2013", "records": 1000},
                         {"name": "LinkedIn", "year": "2012", "records": 2000}],
        }
        findings = analyze(s, "example.com", data)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "medium"
        assert f.source == "breach_check"
        assert f.check_type == "breach_exposure"
        assert f.target == "example.com"
        assert "2 known" in f.title
        assert "XposedOrNot" in f.description
        assert "MFA" in f.remediation
        assert f.extra["breach_count"] == 2
        assert "Adobe" in f.extra["breaches"]

    def test_high_severity_large_account_count(self):
        s = self._session()
        data = {
            "tier": "hibp", "accounts": 250, "breach_count": 3,
            "breaches": [{"name": "Adobe", "year": "2013", "records": 0}],
        }
        f = analyze(s, "example.com", data)[0]
        assert f.severity == "high"
        assert "250 account" in f.title
        assert "Have I Been Pwned" in f.description
        assert f.extra["accounts"] == 250

    def test_high_severity_recent_breach(self):
        s = self._session()
        import datetime
        recent = str(datetime.date.today().year)
        data = {
            "tier": "xposedornot", "accounts": 0, "breach_count": 1,
            "breaches": [{"name": "FreshLeak", "year": recent, "records": 500}],
        }
        f = analyze(s, "example.com", data)[0]
        assert f.severity == "high"
        assert f.extra["recent_breach"] is True

    def test_breach_names_capped(self):
        s = self._session()
        breaches = [{"name": f"Breach{i}", "year": "2015", "records": 0} for i in range(40)]
        data = {"tier": "hibp", "accounts": 5, "breach_count": 40, "breaches": breaches}
        f = analyze(s, "example.com", data)[0]
        assert len(f.extra["breaches"]) == 20

    def test_never_stores_plaintext_credentials_or_emails(self):
        """Privacy invariant: even if the upstream data smuggled per-person PII
        into the record, none of it may appear in any Finding field."""
        s = self._session()
        poisoned = {
            "tier": "hibp",
            "accounts": 2,
            "breach_count": 1,
            "breaches": [{"name": "Adobe", "year": "2013", "records": 100}],
            # simulate leaked per-account data sneaking through
            "aliases": ["jsmith", "adecker"],
            "emails": ["victim@example.com"],
            "password": "SuperSecret123!",
        }
        f = analyze(s, "example.com", poisoned)[0]
        haystack = " ".join([f.title, f.description, f.remediation, f.target, str(f.extra)])
        assert "SuperSecret123!" not in haystack
        assert "victim@example.com" not in haystack
        assert "jsmith" not in haystack
        assert "adecker" not in haystack
        # the public breach name is still surfaced (that's allowed)
        assert "Adobe" in f.extra["breaches"]


# ---------------------------------------------------------------------------
# Scanner — orchestration + persistence
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestScanner:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_saves_finding(self):
        from apps.breach_check.scanner import run_breach_check
        from apps.core.findings.models import Finding
        s = self._session()
        data = {"tier": "xposedornot", "accounts": 0, "breach_count": 2,
                "breaches": [{"name": "Adobe", "year": "2013", "records": 1}]}
        with patch("apps.breach_check.scanner.collect", return_value=data):
            saved = run_breach_check(s)
        assert len(saved) == 1
        assert Finding.objects.filter(session=s, source="breach_check").count() == 1

    def test_no_exposure_saves_nothing(self):
        from apps.breach_check.scanner import run_breach_check
        from apps.core.findings.models import Finding
        s = self._session()
        with patch("apps.breach_check.scanner.collect",
                   return_value={"tier": "xposedornot", "breach_count": 0, "breaches": []}):
            saved = run_breach_check(s)
        assert saved == []
        assert Finding.objects.filter(session=s).count() == 0

    def test_collector_exception_never_fails_scan(self):
        from apps.breach_check.scanner import run_breach_check
        s = self._session()
        with patch("apps.breach_check.scanner.collect", side_effect=RuntimeError("boom")):
            saved = run_breach_check(s)  # must not raise
        assert saved == []

    def test_no_domain_skips(self):
        from apps.breach_check.scanner import run_breach_check
        from apps.core.scans.models import ScanSession
        s = ScanSession.objects.create(domain="", scan_type="full")
        assert run_breach_check(s) == []


# ---------------------------------------------------------------------------
# End-to-end contract — realistic body through real collect -> analyze
# (only requests.get is mocked). Also re-asserts the privacy invariant
# end-to-end for the HIBP alias-keyed body.
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestCollectAnalyzeContract:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    @override_settings(HIBP_API_KEY="secret-key-123")
    def test_hibp_body_end_to_end_no_pii_persisted(self):
        from apps.breach_check.scanner import run_breach_check
        from apps.core.findings.models import Finding

        s = self._session()
        with patch.object(collector.requests, "get", return_value=_resp(json_data=_HIBP_BODY)):
            saved = run_breach_check(s)

        assert len(saved) == 1
        f = Finding.objects.get(session=s, source="breach_check")
        assert f.check_type == "breach_exposure"
        assert f.extra["accounts"] == 3
        assert f.extra["breach_count"] == 3
        assert "Have I Been Pwned" in f.description
        blob = " ".join([f.title, f.description, f.remediation, f.target, str(f.extra)])
        for alias in ("jsmith", "adecker", "root"):
            assert alias not in blob  # PII never persisted end-to-end
