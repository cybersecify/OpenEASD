"""Unit tests for apps/cloud_assets — collector, analyzer, scanner."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from apps.cloud_assets.collector import collect


class TestCollect:
    def test_empty_keywords_returns_empty(self):
        assert collect([]) == []

    @patch("apps.cloud_assets.collector.shutil.which", return_value=None)
    def test_missing_binary_returns_empty(self, _):
        assert collect(["example"]) == []

    @patch("apps.cloud_assets.collector.shutil.which", return_value="/usr/bin/cloud_enum")
    @patch("apps.cloud_assets.collector.subprocess.run")
    def test_nonzero_exit_returns_empty(self, mock_run, _):
        mock_run.return_value = MagicMock(returncode=1, stderr="error")
        assert collect(["example"]) == []

    @patch("apps.cloud_assets.collector.shutil.which", return_value="/usr/bin/cloud_enum")
    @patch("apps.cloud_assets.collector.subprocess.run")
    def test_timeout_returns_empty(self, mock_run, _):
        mock_run.side_effect = subprocess.TimeoutExpired("cloud_enum", 1800)
        assert collect(["example"]) == []

    @patch("apps.cloud_assets.collector.shutil.which", return_value="/usr/bin/cloud_enum")
    @patch("apps.cloud_assets.collector.subprocess.run", return_value=MagicMock(returncode=0, stderr=""))
    @patch("apps.cloud_assets.collector.os.path.exists", return_value=False)
    def test_missing_output_file_returns_empty(self, _exists, _run, _which):
        assert collect(["example"]) == []

    def test_happy_path_returns_aws_url(self, tmp_path):
        keywords_file = tmp_path / "kw.txt"
        output_file = tmp_path / "kw.txt.out"
        output_file.write_text("https://s3.amazonaws.com/example-backup\n")

        mock_ntf = MagicMock()
        mock_ntf.__enter__ = lambda s: s
        mock_ntf.__exit__ = MagicMock(return_value=False)
        mock_ntf.name = str(keywords_file)

        with patch("apps.cloud_assets.collector.shutil.which", return_value="/usr/bin/cloud_enum"), \
             patch("apps.cloud_assets.collector.tempfile.NamedTemporaryFile", return_value=mock_ntf), \
             patch("apps.cloud_assets.collector.subprocess.run", return_value=MagicMock(returncode=0, stderr="")):
            result = collect(["example"])

        assert result == ["https://s3.amazonaws.com/example-backup"]

    def test_all_three_providers_returned(self, tmp_path):
        keywords_file = tmp_path / "kw2.txt"
        output_file = tmp_path / "kw2.txt.out"
        output_file.write_text(
            "https://s3.amazonaws.com/example-data\n"
            "https://example.blob.core.windows.net/files\n"
            "https://storage.googleapis.com/example-backup\n"
        )

        mock_ntf = MagicMock()
        mock_ntf.__enter__ = lambda s: s
        mock_ntf.__exit__ = MagicMock(return_value=False)
        mock_ntf.name = str(keywords_file)

        with patch("apps.cloud_assets.collector.shutil.which", return_value="/usr/bin/cloud_enum"), \
             patch("apps.cloud_assets.collector.tempfile.NamedTemporaryFile", return_value=mock_ntf), \
             patch("apps.cloud_assets.collector.subprocess.run", return_value=MagicMock(returncode=0, stderr="")):
            result = collect(["example"])

        assert len(result) == 3
        assert "https://s3.amazonaws.com/example-data" in result
        assert "https://example.blob.core.windows.net/files" in result
        assert "https://storage.googleapis.com/example-backup" in result


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

from apps.cloud_assets.analyzer import analyze


@pytest.mark.django_db
class TestAnalyze:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_empty_urls_returns_empty(self):
        sess = self._session()
        assert analyze(sess, []) == []

    def test_aws_s3_virtual_hosted_url(self):
        sess = self._session()
        findings = analyze(sess, ["https://example-backup.s3.amazonaws.com"])
        assert len(findings) == 1
        f = findings[0]
        assert f.source == "cloud_assets"
        assert f.check_type == "open_cloud_bucket"
        assert f.severity == "high"
        assert f.extra["provider"] == "aws"
        assert f.extra["bucket_name"] == "example-backup"
        assert "example-backup" in f.title

    def test_aws_s3_path_style_url(self):
        sess = self._session()
        findings = analyze(sess, ["https://s3.amazonaws.com/example-data"])
        assert len(findings) == 1
        assert findings[0].extra["provider"] == "aws"
        assert findings[0].extra["bucket_name"] == "example-data"

    def test_azure_blob_url(self):
        sess = self._session()
        findings = analyze(sess, ["https://myaccount.blob.core.windows.net/container"])
        assert len(findings) == 1
        assert findings[0].extra["provider"] == "azure"
        assert findings[0].extra["bucket_name"] == "myaccount"

    def test_gcp_storage_url(self):
        sess = self._session()
        findings = analyze(sess, ["https://storage.googleapis.com/example-bucket"])
        assert len(findings) == 1
        assert findings[0].extra["provider"] == "gcp"
        assert findings[0].extra["bucket_name"] == "example-bucket"

    def test_duplicate_urls_deduped(self):
        sess = self._session()
        url = "https://s3.amazonaws.com/example-data"
        findings = analyze(sess, [url, url])
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

from apps.cloud_assets.scanner import _derive_keywords, run_cloud_assets


class TestDeriveKeywords:
    def test_apex_label_included(self):
        result = _derive_keywords("example.com", [])
        assert "example" in result

    def test_subdomain_leftmost_label_included(self):
        result = _derive_keywords("example.com", ["dev.example.com", "api.example.com"])
        assert "dev" in result
        assert "api" in result

    def test_short_labels_filtered(self):
        result = _derive_keywords("example.com", ["s3.example.com", "ns.example.com"])
        assert "s3" not in result
        assert "ns" not in result

    def test_deduplication(self):
        result = _derive_keywords("dev.com", ["dev.dev.com"])
        assert result.count("dev") == 1


@pytest.mark.django_db
class TestScanner:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_no_subdomains_skips_collect(self):
        sess = self._session()
        with patch("apps.cloud_assets.scanner.collect") as mock_collect:
            result = run_cloud_assets(sess)
        assert result == []
        mock_collect.assert_not_called()

    def test_happy_path_persists_and_returns_findings(self):
        from apps.core.assets.models import Subdomain
        from apps.core.findings.models import Finding

        sess = self._session()
        Subdomain.objects.create(
            session=sess, domain="example.com",
            subdomain="dev.example.com", source="subfinder",
        )

        with patch("apps.cloud_assets.scanner.collect",
                   return_value=["https://s3.amazonaws.com/example-backup"]):
            result = run_cloud_assets(sess)

        assert len(result) == 1
        assert Finding.objects.filter(session=sess, source="cloud_assets").count() == 1
        assert result[0].check_type == "open_cloud_bucket"
        assert result[0].severity == "high"

    def test_collect_returns_empty_no_findings(self):
        from apps.core.assets.models import Subdomain

        sess = self._session()
        Subdomain.objects.create(
            session=sess, domain="example.com",
            subdomain="dev.example.com", source="subfinder",
        )
        with patch("apps.cloud_assets.scanner.collect", return_value=[]):
            result = run_cloud_assets(sess)
        assert result == []
