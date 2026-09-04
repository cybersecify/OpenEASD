"""Unit tests for apps/github_recon — collector (two-tier BYO-token), infra-reference
extraction, analyzer, scanner.

github_recon is a passive tool: it enumerates the target org's PUBLIC GitHub repos
via GitHub's official REST API and surfaces exposed infrastructure references
(internal hostnames/subdomains, cloud-bucket URLs, API endpoints) in that public
code/config. It must be fail-graceful (never raise) and stay within a capped request
budget so the unauthenticated free tier (60 req/hr) is never blown.
"""

import base64
import re

import pytest
import requests
from unittest.mock import MagicMock, patch

from apps.github_recon.analyzer import analyze, extract_infra_refs
from apps.github_recon.collector import _resolve_org, collect
from apps.github_recon.scanner import run_github_recon


def _session(domain="example.com"):
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain=domain, scan_type="full")


def _resp(status=200, json_body=None, headers=None):
    r = MagicMock()
    r.status_code = status
    r.headers = headers or {}
    r.json.return_value = json_body if json_body is not None else {}
    return r


def _b64_file(text, size=None):
    encoded = base64.b64encode(text.encode()).decode()
    return {"encoding": "base64", "content": encoded, "size": size if size is not None else len(text)}


def _router(handlers):
    """Build a requests.get side_effect that dispatches on the URL.

    handlers: list of (path_pattern, response). First pattern that matches the
    request URL (via re.search — avoids a flagged `needle in url` substring check)
    wins. A final catch-all 404 is returned otherwise.
    """
    def _get(url, params=None, headers=None, timeout=None):
        for pattern, resp in handlers:
            if re.search(pattern, url):
                return resp
        return _resp(status=404)
    return _get


# ---------------------------------------------------------------------------
# Org resolution
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestResolveOrg:
    def test_derives_registrable_label(self, settings):
        settings.GITHUB_ORG = ""
        assert _resolve_org("example.com") == "example"

    def test_strips_subdomain(self, settings):
        settings.GITHUB_ORG = ""
        assert _resolve_org("www.example.com") == "example"

    def test_override_wins(self, settings):
        settings.GITHUB_ORG = "acme-labs"
        assert _resolve_org("example.com") == "acme-labs"

    def test_empty_domain(self, settings):
        settings.GITHUB_ORG = ""
        assert _resolve_org("") is None


# ---------------------------------------------------------------------------
# Collector — enumeration happy paths
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestCollectorEnumeration:
    def _org_ok(self, login="example"):
        return _resp(json_body={"login": login, "html_url": f"https://github.com/{login}"})

    def test_org_confirmed_and_repos_parsed(self, settings):
        settings.GITHUB_ORG = ""
        settings.GITHUB_TOKEN = ""
        repos = [{"name": "web", "full_name": "example/web", "description": "d",
                  "homepage": "https://example.com", "topics": ["infra"],
                  "html_url": "https://github.com/example/web", "fork": False, "size": 1}]
        handlers = [
            ("/orgs/example/repos", _resp(json_body=repos)),
            ("/orgs/example", self._org_ok()),
            ("/contents/", _resp(status=404)),
        ]
        with patch("apps.github_recon.collector.requests.get", side_effect=_router(handlers)):
            data = collect("example.com")
        assert data["org_confirmed"] is True
        assert data["org"] == "example"
        assert data["kind"] == "org"
        assert [r["name"] for r in data["repos"]] == ["web"]

    def test_repos_endpoint_uses_orgs_path_first(self, settings):
        settings.GITHUB_ORG = ""
        settings.GITHUB_TOKEN = ""
        captured = {}

        def _get(url, params=None, headers=None, timeout=None):
            if url.endswith("/orgs/example"):
                return self._org_ok()
            if "/orgs/example/repos" in url:
                captured["repos_url"] = url
                return _resp(json_body=[])
            return _resp(status=404)

        with patch("apps.github_recon.collector.requests.get", side_effect=_get):
            collect("example.com")
        assert captured["repos_url"].startswith("https://api.github.com/orgs/example/repos")

    def test_user_fallback_when_org_404(self, settings):
        settings.GITHUB_ORG = ""
        settings.GITHUB_TOKEN = ""
        handlers = [
            ("/users/example/repos", _resp(json_body=[])),
            ("/orgs/example", _resp(status=404)),
            ("/users/example", _resp(json_body={"login": "example", "type": "User",
                                                "html_url": "https://github.com/example"})),
        ]
        with patch("apps.github_recon.collector.requests.get", side_effect=_router(handlers)):
            data = collect("example.com")
        assert data["org_confirmed"] is True
        assert data["kind"] == "user"

    def test_unknown_account_not_confirmed(self, settings):
        settings.GITHUB_ORG = ""
        settings.GITHUB_TOKEN = ""
        with patch("apps.github_recon.collector.requests.get", return_value=_resp(status=404)):
            data = collect("example.com")
        assert data["org_confirmed"] is False
        assert data["repos"] == []

    def test_forks_skipped(self, settings):
        settings.GITHUB_ORG = ""
        settings.GITHUB_TOKEN = ""
        repos = [
            {"name": "own", "fork": False, "html_url": "u"},
            {"name": "forked", "fork": True, "html_url": "u"},
        ]
        handlers = [("/orgs/example/repos", _resp(json_body=repos)),
                    ("/orgs/example", self._org_ok())]
        with patch("apps.github_recon.collector.requests.get", side_effect=_router(handlers)):
            data = collect("example.com")
        assert [r["name"] for r in data["repos"]] == ["own"]

    def test_repos_capped_at_max(self, settings):
        settings.GITHUB_ORG = ""
        settings.GITHUB_TOKEN = ""
        settings.GITHUB_MAX_REPOS = 3
        settings.GITHUB_MAX_REQUESTS = 100
        repos = [{"name": f"r{i}", "fork": False, "html_url": "u"} for i in range(50)]
        handlers = [("/orgs/example/repos", _resp(json_body=repos)),
                    ("/orgs/example", self._org_ok()),
                    ("/contents/", _resp(status=404))]
        with patch("apps.github_recon.collector.requests.get", side_effect=_router(handlers)):
            data = collect("example.com")
        assert len(data["repos"]) == 3

    def test_config_file_fetched_and_decoded(self, settings):
        settings.GITHUB_ORG = ""
        settings.GITHUB_TOKEN = ""
        settings.GITHUB_MAX_REQUESTS = 100
        repos = [{"name": "web", "fork": False, "html_url": "u"}]
        readme = _b64_file("see internal.example.com and s3://acme-backups")
        handlers = [
            ("/orgs/example/repos", _resp(json_body=repos)),
            ("/orgs/example", self._org_ok()),
            ("/contents/README.md", _resp(json_body=readme)),
            ("/contents/", _resp(status=404)),
        ]
        with patch("apps.github_recon.collector.requests.get", side_effect=_router(handlers)):
            data = collect("example.com")
        files = data["repos"][0]["files"]
        assert files and files[0]["path"] == "README.md"
        assert files[0]["content"] == "see internal.example.com and s3://acme-backups"

    def test_oversized_file_skipped(self, settings):
        settings.GITHUB_ORG = ""
        settings.GITHUB_TOKEN = ""
        repos = [{"name": "web", "fork": False, "html_url": "u"}]
        big = _b64_file("x", size=999_999)
        handlers = [("/orgs/example/repos", _resp(json_body=repos)),
                    ("/orgs/example", self._org_ok()),
                    ("/contents/", _resp(json_body=big))]
        with patch("apps.github_recon.collector.requests.get", side_effect=_router(handlers)):
            data = collect("example.com")
        assert data["repos"][0]["files"] == []

    def test_request_budget_caps_total_calls(self, settings):
        settings.GITHUB_ORG = ""
        settings.GITHUB_TOKEN = ""
        settings.GITHUB_MAX_REPOS = 50
        settings.GITHUB_MAX_REQUESTS = 3  # confirm(1) + repos(1) leaves ~1 for files
        repos = [{"name": f"r{i}", "fork": False, "html_url": "u"} for i in range(10)]
        calls = {"n": 0}

        def _get(url, params=None, headers=None, timeout=None):
            calls["n"] += 1
            if url.endswith("/orgs/example"):
                return self._org_ok()
            if "/orgs/example/repos" in url:
                return _resp(json_body=repos)
            return _resp(status=404)

        with patch("apps.github_recon.collector.requests.get", side_effect=_get):
            collect("example.com")
        assert calls["n"] <= 3  # never exceeds GITHUB_MAX_REQUESTS

    def test_token_sets_auth_header(self, settings):
        settings.GITHUB_ORG = ""
        settings.GITHUB_TOKEN = "ghp_secret"
        captured = {}

        def _get(url, params=None, headers=None, timeout=None):
            captured["headers"] = headers
            return _resp(status=404)

        with patch("apps.github_recon.collector.requests.get", side_effect=_get):
            collect("example.com")
        assert captured["headers"]["Authorization"] == "Bearer ghp_secret"

    def test_no_token_no_auth_header(self, settings):
        settings.GITHUB_ORG = ""
        settings.GITHUB_TOKEN = ""
        captured = {}

        def _get(url, params=None, headers=None, timeout=None):
            captured["headers"] = headers
            return _resp(status=404)

        with patch("apps.github_recon.collector.requests.get", side_effect=_get):
            collect("example.com")
        assert "Authorization" not in captured["headers"]
        assert captured["headers"]["User-Agent"]  # honest UA always sent


# ---------------------------------------------------------------------------
# Collector — fail-graceful contract
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestCollectorFailGraceful:
    def test_request_exception_never_raises(self, settings):
        settings.GITHUB_ORG = ""
        settings.GITHUB_TOKEN = ""
        with patch("apps.github_recon.collector.requests.get",
                   side_effect=requests.RequestException("boom")):
            data = collect("example.com")
        assert data["org_confirmed"] is False

    def test_500_never_raises(self, settings):
        settings.GITHUB_ORG = ""
        settings.GITHUB_TOKEN = ""
        with patch("apps.github_recon.collector.requests.get", return_value=_resp(status=500)):
            assert collect("example.com")["org_confirmed"] is False

    def test_rate_limit_retries_then_gives_up(self, settings):
        settings.GITHUB_ORG = ""
        settings.GITHUB_TOKEN = ""
        limited = _resp(status=403, headers={"Retry-After": "0", "X-RateLimit-Remaining": "0"})
        with patch("apps.github_recon.collector.requests.get", return_value=limited), \
             patch("apps.github_recon.collector.time.sleep") as slept:
            data = collect("example.com")
        assert data["org_confirmed"] is False
        assert slept.called  # honoured the backoff before giving up

    def test_hard_403_not_retried(self, settings):
        settings.GITHUB_ORG = ""
        settings.GITHUB_TOKEN = ""
        # A 403 that is NOT a rate limit (no Retry-After, remaining not zero).
        forbidden = _resp(status=403, headers={"X-RateLimit-Remaining": "42"})
        with patch("apps.github_recon.collector.requests.get", return_value=forbidden), \
             patch("apps.github_recon.collector.time.sleep") as slept:
            data = collect("example.com")
        assert data["org_confirmed"] is False
        assert not slept.called  # did not treat a hard 403 as a rate limit

    def test_bad_json_never_raises(self, settings):
        settings.GITHUB_ORG = ""
        settings.GITHUB_TOKEN = ""
        r = _resp(status=200)
        r.json.side_effect = ValueError("not json")
        with patch("apps.github_recon.collector.requests.get", return_value=r):
            assert collect("example.com")["org_confirmed"] is False


# ---------------------------------------------------------------------------
# Infra-reference extraction
# ---------------------------------------------------------------------------

class TestExtractInfraRefs:
    def test_subdomain_hostname(self):
        refs = extract_infra_refs("connect to internal.example.com now", "example.com")
        assert ("hostname", "internal.example.com") in refs

    def test_api_subdomain_classified_as_api(self):
        refs = extract_infra_refs("base https://api.example.com/v1", "example.com")
        assert ("api_endpoint", "api.example.com") in refs

    def test_api_path_on_apex(self):
        refs = extract_infra_refs("call https://example.com/api/v1/users", "example.com")
        assert ("api_endpoint", "https://example.com/api/v1/users") in refs

    def test_apex_alone_not_reported(self):
        # The bare apex is not an interesting infra leak — only subdomains/URLs are.
        refs = extract_infra_refs("visit example.com", "example.com")
        assert refs == set()

    def test_s3_bucket_uri(self):
        refs = extract_infra_refs("backup to s3://acme-prod-backups/db", "example.com")
        # The bucket name is the identifier we surface (object path is dropped).
        assert ("cloud_bucket", "s3://acme-prod-backups") in refs

    def test_s3_virtual_host(self):
        refs = extract_infra_refs("https://assets.s3.amazonaws.com/logo.png", "example.com")
        assert ("cloud_bucket", "assets.s3.amazonaws.com") in refs

    def test_azure_blob(self):
        refs = extract_infra_refs("https://acmestore.blob.core.windows.net/x", "example.com")
        assert ("cloud_bucket", "acmestore.blob.core.windows.net") in refs

    def test_gcp_bucket(self):
        refs = extract_infra_refs("gs at storage.googleapis.com/acme-assets", "example.com")
        assert ("cloud_bucket", "storage.googleapis.com/acme-assets") in refs

    def test_empty_and_none(self):
        assert extract_infra_refs("", "example.com") == set()
        assert extract_infra_refs("nothing here", "example.com") == set()
        assert extract_infra_refs("internal.example.com", "") == set()


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAnalyzer:
    def _data(self, repos, org="example", confirmed=True):
        return {"org": org, "org_confirmed": confirmed, "kind": "org",
                "org_url": f"https://github.com/{org}", "repos": repos}

    def test_summary_finding_emitted(self):
        sess = _session()
        data = self._data([{"name": "web", "html_url": "u", "description": "", "topics": [], "files": []}])
        findings = analyze(sess, "example.com", data)
        summary = [f for f in findings if f.check_type == "github_public_repos"]
        assert len(summary) == 1
        assert summary[0].severity == "info"
        assert summary[0].source == "github_recon"
        assert summary[0].extra["repo_count"] == 1

    def test_infra_finding_shape(self):
        sess = _session()
        repo = {"name": "web", "html_url": "https://github.com/example/web",
                "description": "uses internal.example.com", "topics": [], "files": []}
        findings = analyze(sess, "example.com", self._data([repo]))
        infra = [f for f in findings if f.check_type == "github_infra_exposure"]
        assert len(infra) == 1
        f = infra[0]
        assert f.severity == "low"
        assert f.source == "github_recon"
        assert f.target == "internal.example.com"
        assert f.extra["ref_type"] == "hostname"
        assert f.extra["repo"] == "web"
        assert f.extra["source_data"] == "github_recon"

    def test_refs_deduped_across_repos(self):
        sess = _session()
        repos = [
            {"name": "a", "html_url": "u", "description": "internal.example.com", "topics": [], "files": []},
            {"name": "b", "html_url": "u", "description": "internal.example.com", "topics": [], "files": []},
        ]
        findings = analyze(sess, "example.com", self._data(repos))
        infra = [f for f in findings if f.check_type == "github_infra_exposure"]
        assert len(infra) == 1  # same reference reported once

    def test_no_summary_when_unconfirmed(self):
        sess = _session()
        findings = analyze(sess, "example.com", self._data([], confirmed=False))
        assert findings == []

    def test_finding_from_file_content(self):
        sess = _session()
        repo = {"name": "web", "html_url": "u", "description": "", "topics": [],
                "files": [{"path": "README.md", "content": "bucket s3://acme-prod"}]}
        findings = analyze(sess, "example.com", self._data([repo]))
        buckets = [f for f in findings if f.extra.get("ref_type") == "cloud_bucket"]
        assert buckets and buckets[0].extra["location"] == "file:README.md"

    def test_non_dict_data_safe(self):
        assert analyze(_session(), "example.com", None) == []


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestScanner:
    def test_saves_findings(self):
        from apps.core.findings.models import Finding
        sess = _session()
        data = {"org": "example", "org_confirmed": True, "kind": "org",
                "org_url": "https://github.com/example",
                "repos": [{"name": "web", "html_url": "u",
                           "description": "internal.example.com", "topics": [], "files": []}]}
        with patch("apps.github_recon.scanner.collect", return_value=data):
            saved = run_github_recon(sess)
        assert len(saved) == 2  # summary + one infra exposure
        assert Finding.objects.filter(session=sess, source="github_recon").count() == 2

    def test_empty_when_no_data(self):
        sess = _session()
        with patch("apps.github_recon.scanner.collect",
                   return_value={"org": None, "org_confirmed": False, "repos": []}):
            assert run_github_recon(sess) == []

    def test_never_raises_on_collect_error(self):
        sess = _session()
        with patch("apps.github_recon.scanner.collect", side_effect=RuntimeError("boom")):
            assert run_github_recon(sess) == []

    def test_no_domain_skips(self):
        sess = _session(domain="")
        assert run_github_recon(sess) == []
