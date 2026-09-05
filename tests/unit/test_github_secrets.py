"""Unit tests for apps/github_secrets — collector, analyzer, scanner.

github_secrets is a PASSIVE, bring-your-own-key tool: it searches PUBLIC GitHub's
code-search API (a third party, never the target) for the org's leaked secrets
and runs gitleaks over the hits. BYOK is MANDATORY (code-search needs auth): no
GITHUB_TOKEN -> logged no-op. It must be fail-graceful on the GitHub API side
(never raise), while only a missing/timed-out gitleaks binary raises. Redaction
is a hard requirement — the full secret must NEVER be persisted.
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest
import requests

from apps.github_secrets.analyzer import _redact, _scrub_match, analyze
from apps.github_secrets.collector import (
    _build_queries,
    _candidate_org,
    _is_rate_limited,
    _sleep_for_rate_limit,
    collect,
)
from apps.github_secrets.scanner import run_github_secrets
from apps.core.workflows.exceptions import ToolBinaryMissing, ToolTimeout


def _session(domain="acme.com"):
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain=domain, scan_type="full")


def _resp(status=200, json_body=None, text=None, headers=None):
    r = MagicMock()
    r.status_code = status
    r.headers = headers or {}
    if json_body is not None:
        r.json.return_value = json_body
    else:
        r.json.side_effect = ValueError("no json")
    r.text = text if text is not None else ""
    return r


# ---------------------------------------------------------------------------
# BYOK gate — no token is a logged no-op
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestNoTokenSkip:
    def test_no_token_returns_empty_and_makes_no_request(self, settings):
        settings.GITHUB_TOKEN = ""
        with patch("apps.github_secrets.collector.requests.get") as g:
            assert collect(_session()) == []
        g.assert_not_called()

    def test_whitespace_token_treated_as_absent(self, settings):
        settings.GITHUB_TOKEN = "   "
        with patch("apps.github_secrets.collector.requests.get") as g:
            assert collect(_session()) == []
        g.assert_not_called()


# ---------------------------------------------------------------------------
# Org resolution + query building (org-scoping)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestOrgResolution:
    def test_override_is_high_confidence(self, settings):
        settings.GITHUB_ORG = "acmecorp"
        org, confident = _candidate_org(_session("acme.com"))
        assert org == "acmecorp"
        assert confident is True

    def test_derived_from_apex_label_low_confidence(self, settings):
        settings.GITHUB_ORG = ""
        org, confident = _candidate_org(_session("acme.com"))
        assert org == "acme"
        assert confident is False

    def test_www_prefix_stripped(self, settings):
        settings.GITHUB_ORG = ""
        org, _ = _candidate_org(_session("www.acme.com"))
        assert org == "acme"

    def test_empty_domain_no_override_returns_empty(self, settings):
        settings.GITHUB_ORG = ""
        org, confident = _candidate_org(_session(""))
        assert org == ""
        assert confident is False


@pytest.mark.django_db
class TestQueryBuilding:
    def test_queries_are_org_scoped_by_default(self, settings):
        settings.GITHUB_SECRETS_GLOBAL_SEARCH = False
        queries = _build_queries(_session("acme.com"), "acme")
        assert queries, "expected at least one query"
        for q in queries:
            assert q.startswith("org:acme"), f"non-org-scoped query leaked: {q}"

    def test_global_search_opt_in_adds_unscoped_query(self, settings):
        settings.GITHUB_SECRETS_GLOBAL_SEARCH = True
        queries = _build_queries(_session("acme.com"), "acme")
        unscoped = [q for q in queries if not q.startswith("org:")]
        assert unscoped == ['"acme.com"']

    def test_queries_bounded_by_max(self, settings):
        from apps.github_secrets import collector
        settings.GITHUB_SECRETS_GLOBAL_SEARCH = True
        queries = _build_queries(_session("acme.com"), "acme")
        assert len(queries) <= collector.MAX_SEARCH_QUERIES


# ---------------------------------------------------------------------------
# Rate-limit helpers
# ---------------------------------------------------------------------------

class TestRateLimitHelpers:
    def test_429_is_rate_limited(self):
        assert _is_rate_limited(_resp(status=429)) is True

    def test_403_with_zero_remaining_is_rate_limited(self):
        assert _is_rate_limited(_resp(status=403, headers={"X-RateLimit-Remaining": "0"})) is True

    def test_403_secondary_limit_retry_after_is_rate_limited(self):
        assert _is_rate_limited(_resp(status=403, headers={"Retry-After": "3"})) is True

    def test_plain_403_not_rate_limited(self):
        assert _is_rate_limited(_resp(status=403, headers={"X-RateLimit-Remaining": "42"})) is False

    def test_backoff_prefers_retry_after_capped(self):
        r = _resp(status=429, headers={"Retry-After": "9999"})
        from apps.github_secrets import collector
        assert _sleep_for_rate_limit(r) == float(collector._MAX_BACKOFF)

    def test_backoff_falls_back_to_reset_header(self):
        import time
        r = _resp(status=429, headers={"X-RateLimit-Reset": str(int(time.time()) + 5)})
        assert 0 < _sleep_for_rate_limit(r) <= 15


# ---------------------------------------------------------------------------
# Collector fail-graceful — GitHub API errors NEVER raise
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestCollectorFailGraceful:
    def _prime(self, settings):
        settings.GITHUB_TOKEN = "tok"
        settings.GITHUB_ORG = "acme"
        settings.GITHUB_SECRETS_GLOBAL_SEARCH = False

    def test_network_error_never_raises(self, settings):
        self._prime(settings)
        with patch("apps.github_secrets.collector.requests.get",
                   side_effect=requests.ConnectionError("boom")):
            assert collect(_session()) == []

    def test_http_500_never_raises(self, settings):
        self._prime(settings)
        with patch("apps.github_secrets.collector.requests.get",
                   return_value=_resp(status=500)):
            assert collect(_session()) == []

    def test_rate_limit_exhausted_never_raises(self, settings):
        self._prime(settings)
        with patch("apps.github_secrets.collector.requests.get",
                   return_value=_resp(status=429, headers={"Retry-After": "0"})), \
             patch("apps.github_secrets.collector.time.sleep"):
            assert collect(_session()) == []

    def test_rate_limit_then_success_backs_off(self, settings):
        """A 429 is retried after a capped sleep, then succeeds."""
        self._prime(settings)
        limited = _resp(status=429, headers={"Retry-After": "1"})
        ok_org = _resp(status=200, json_body={"login": "acme"})
        empty_search = _resp(status=200, json_body={"items": []})
        seq = [limited, ok_org] + [empty_search] * 20
        with patch("apps.github_secrets.collector.requests.get", side_effect=seq), \
             patch("apps.github_secrets.collector.time.sleep") as slept:
            assert collect(_session()) == []
        slept.assert_called()  # backoff actually happened

    def test_bad_json_search_never_raises(self, settings):
        self._prime(settings)
        ok_org = _resp(status=200, json_body={"login": "acme"})
        bad = _resp(status=200, json_body=None)  # .json() raises ValueError
        with patch("apps.github_secrets.collector.requests.get",
                   side_effect=[ok_org] + [bad] * 20):
            assert collect(_session()) == []


# ---------------------------------------------------------------------------
# Collector happy path — search -> fetch -> gitleaks
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestCollectorHappyPath:
    def _search_item(self):
        return {
            "url": "https://api.github.com/repos/acme/app/contents/.env",
            "html_url": "https://github.com/acme/app/blob/main/.env",
            "sha": "abc123",
            "path": ".env",
            "repository": {"full_name": "acme/app"},
        }

    def test_search_fetch_gitleaks_tags_records(self, settings):
        settings.GITHUB_TOKEN = "tok"
        settings.GITHUB_ORG = "acme"
        settings.GITHUB_SECRETS_GLOBAL_SEARCH = False

        ok_org = _resp(status=200, json_body={"login": "acme"})
        search_hit = _resp(status=200, json_body={"items": [self._search_item()]})
        empty_search = _resp(status=200, json_body={"items": []})
        blob = _resp(status=200, text="AWS_KEY=AKIAEXAMPLEKEY1234567")

        # org confirm, then 6 search queries (1 hit + 5 empty), then 1 blob fetch
        seq = [ok_org, search_hit] + [empty_search] * 5 + [blob]

        gitleaks_records = [{
            "RuleID": "aws-access-token",
            "Description": "AWS Access Key",
            "File": "/tmp/x/0.txt",
            "Secret": "AKIAEXAMPLEKEY1234567",
            "Match": 'AWS_KEY=AKIAEXAMPLEKEY1234567',
            "StartLine": 1,
        }]

        with patch("apps.github_secrets.collector.requests.get", side_effect=seq), \
             patch("apps.github_secrets.collector._run_gitleaks", return_value=gitleaks_records):
            records = collect(_session("acme.com"))

        assert len(records) == 1
        rec = records[0]
        assert rec["_repo"] == "acme/app"
        assert rec["_source_url"] == "https://github.com/acme/app/blob/main/.env"
        assert rec["RuleID"] == "aws-access-token"


# ---------------------------------------------------------------------------
# _run_gitleaks — binary missing / timeout DO raise (like js_secrets)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestGitleaksBinary:
    def test_binary_missing_raises(self, settings, tmp_path):
        from apps.github_secrets.collector import _run_gitleaks
        with patch("apps.github_secrets.collector.subprocess.run",
                   side_effect=FileNotFoundError()):
            with pytest.raises(ToolBinaryMissing):
                _run_gitleaks(_session(), str(tmp_path))

    def test_timeout_raises(self, settings, tmp_path):
        from apps.github_secrets.collector import _run_gitleaks
        with patch("apps.github_secrets.collector.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd="gitleaks", timeout=1)):
            with pytest.raises(ToolTimeout):
                _run_gitleaks(_session(), str(tmp_path))


# ---------------------------------------------------------------------------
# Redaction — the hard requirement
# ---------------------------------------------------------------------------

class TestRedaction:
    def test_short_secret_fully_masked(self):
        assert _redact("abc") == "***"

    def test_long_secret_partially_masked_no_plaintext(self):
        secret = "AKIAEXAMPLEKEY1234567"
        red = _redact(secret)
        assert secret not in red
        assert red.startswith("AKIA")
        assert "chars" in red

    def test_scrub_match_removes_raw_secret(self):
        secret = "AKIAEXAMPLEKEY1234567"
        match = f'AWS_KEY="{secret}"'
        scrubbed = _scrub_match(match, secret)
        assert secret not in scrubbed


# ---------------------------------------------------------------------------
# Analyzer — Finding shape, redaction persisted, dedup
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAnalyzer:
    def _rec(self, line=1, url="https://github.com/acme/app/blob/main/.env"):
        return {
            "RuleID": "aws-access-token",
            "Description": "AWS Access Key",
            "Secret": "AKIAEXAMPLEKEY1234567",
            "Match": 'AWS_KEY="AKIAEXAMPLEKEY1234567"',
            "StartLine": line,
            "_source_url": url,
            "_repo": "acme/app",
        }

    def test_finding_shape(self):
        findings = analyze(_session(), [self._rec()])
        assert len(findings) == 1
        f = findings[0]
        assert f.source == "github_secrets"
        assert f.check_type == "exposed_secret"
        assert f.severity == "high"
        assert f.extra["origin"] == "github"
        assert f.extra["repo"] == "acme/app"
        assert f.extra["rule_id"] == "aws-access-token"
        assert f.target.startswith("https://github.com/acme/app")

    def test_full_secret_never_persisted_in_any_field(self):
        secret = "AKIAEXAMPLEKEY1234567"
        f = analyze(_session(), [self._rec()])[0]
        haystack = " ".join([
            f.title, f.description, f.remediation, f.target,
            str(f.extra),
        ])
        assert secret not in haystack, "full secret leaked into a persisted field!"

    def test_dedup_by_rule_url_line(self):
        recs = [self._rec(line=1), self._rec(line=1), self._rec(line=2)]
        findings = analyze(_session(), recs)
        assert len(findings) == 2  # line 1 deduped, line 2 distinct

    def test_empty_records_returns_empty(self):
        assert analyze(_session(), []) == []


# ---------------------------------------------------------------------------
# Scanner — orchestration + never-fail-a-scan for the API side
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestScanner:
    def test_no_token_saves_nothing(self, settings):
        settings.GITHUB_TOKEN = ""
        assert run_github_secrets(_session()) == []

    def test_saves_findings_and_persists_redacted(self, settings):
        from apps.core.findings.models import Finding
        secret = "AKIAEXAMPLEKEY1234567"
        rec = {
            "RuleID": "aws-access-token",
            "Description": "AWS Access Key",
            "Secret": secret,
            "Match": f'AWS_KEY="{secret}"',
            "StartLine": 1,
            "_source_url": "https://github.com/acme/app/blob/main/.env",
            "_repo": "acme/app",
        }
        sess = _session("acme.com")
        with patch("apps.github_secrets.scanner.collect", return_value=[rec]):
            saved = run_github_secrets(sess)
        assert len(saved) == 1
        stored = Finding.objects.get(session=sess, source="github_secrets")
        assert stored.check_type == "exposed_secret"
        # DB-level assertion: the raw secret is nowhere in the stored row.
        assert secret not in str(stored.extra)
        assert secret not in stored.description
