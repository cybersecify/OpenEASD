# Cloud Assets Tool — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `apps/cloud_assets/` — a Phase 4 tool that runs `cloud_enum` to find publicly accessible AWS S3, Azure Blob, and GCP Storage buckets associated with a domain, and saves each as a `Finding`.

**Architecture:** Standard 5-file tool app following the `collector → analyzer → scanner` pattern used by every other tool in the repo. `cloud_enum` (Python CLI, `pip install cloud-enum`) generates keyword permutations and probes all three cloud providers. Keywords come from the apex domain label + leftmost subdomain labels already in the session. Findings go straight to `apps/core/findings/Finding` — no new models, no migrations. 20 unit tests: TestCollect (7), TestAnalyze (6), TestDeriveKeywords (4), TestScanner (3).

**Tech Stack:** Python 3.12, Django 5, `cloud_enum` CLI (PyPI: `cloud-enum`), `apps/core/findings/Finding`, `apps/core/assets/Subdomain`.

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Create | `apps/cloud_assets/__init__.py` | Python package marker (empty) |
| Create | `apps/cloud_assets/apps.py` | `AppConfig` + `tool_meta` (self-registration) |
| Create | `apps/cloud_assets/models.py` | Empty — no new models |
| Create | `apps/cloud_assets/collector.py` | Writes keywords file → runs `cloud_enum -kf … -l …` → returns open bucket URLs |
| Create | `apps/cloud_assets/analyzer.py` | Parses URLs → identifies provider/bucket → returns `Finding` objects |
| Create | `apps/cloud_assets/scanner.py` | Derives keywords from session → calls collect+analyze → bulk saves findings |
| Create | `tests/unit/test_cloud_assets.py` | 17 unit tests: TestCollect (7), TestAnalyze (6), TestScanner (4) |
| Modify | `pyproject.toml` | Add `cloud-enum` to `[project.dependencies]` |
| Modify | `openeasd/settings.py` | Add `TOOL_CLOUD_ENUM` setting + `"apps.cloud_assets"` to `INSTALLED_APPS` |

---

## Task 1: App Skeleton + Wiring

**Files:**
- Create: `apps/cloud_assets/__init__.py`
- Create: `apps/cloud_assets/models.py`
- Create: `apps/cloud_assets/apps.py`
- Modify: `pyproject.toml`
- Modify: `openeasd/settings.py`

- [ ] **Step 1: Create the package marker and empty models**

```bash
mkdir -p apps/cloud_assets
```

`apps/cloud_assets/__init__.py` — empty file.

`apps/cloud_assets/models.py`:
```python
# No models — findings go to apps/core/findings/Finding
```

- [ ] **Step 2: Create apps.py**

`apps/cloud_assets/apps.py`:
```python
from django.apps import AppConfig


class CloudAssetsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.cloud_assets"
    label = "cloud_assets"
    verbose_name = "Cloud Assets"
    tool_meta = {
        "label": "Cloud Assets",
        "runner": "apps.cloud_assets.scanner.run_cloud_assets",
        "phase": 4,
        "phase_group": "Surface Enumeration",
        "requires": ["subfinder"],
        "produces_findings": True,
    }
```

- [ ] **Step 3: Add cloud-enum dependency to pyproject.toml**

In `pyproject.toml`, add `cloud-enum` to the `[project.dependencies]` list after `"urllib3>=2.7.0"`:

```toml
    "cloud-enum",
```

The full dependencies block should end with:
```toml
    "urllib3>=2.7.0",
    "idna>=3.15",
    "cloud-enum",
]
```

> **Note:** Verify that `cloud-enum` is on PyPI by running `pip index versions cloud-enum` or checking https://pypi.org/project/cloud-enum/. If it is not on PyPI, install from GitHub instead: `"cloud-enum @ git+https://github.com/initstring/cloud_enum.git"`. The installed command is `cloud_enum` (underscore) in both cases.

- [ ] **Step 4: Wire settings.py**

In `openeasd/settings.py`, add after `TOOL_ALTERX`:
```python
TOOL_CLOUD_ENUM = config("TOOL_CLOUD_ENUM", default="cloud_enum")
```

In `INSTALLED_APPS`, add `"apps.cloud_assets"` immediately after `"apps.takeover_check"`:
```python
    "apps.takeover_check",
    "apps.cloud_assets",
    "apps.naabu",
```

- [ ] **Step 5: Install dependency and verify app loads**

```bash
uv sync
uv run manage.py check
```

Expected: `System check identified no issues (0 silenced).`

- [ ] **Step 6: Commit skeleton**

```bash
git checkout -b feat/cloud-assets-tool
git add apps/cloud_assets/ pyproject.toml openeasd/settings.py
git commit -m "feat: add cloud_assets app skeleton and wiring"
```

---

## Task 2: Collector

**Files:**
- Create: `apps/cloud_assets/collector.py`
- Create: `tests/unit/test_cloud_assets.py` (TestCollect class only)

The collector writes keywords to a temp file, runs `cloud_enum`, reads the output file (one open bucket URL per line), and returns the URL list.

> **Before implementing:** Verify the exact `cloud_enum` flags by running `cloud_enum --help`. The flags used below are: `-kf <keyfile>` (keyword file), `-l <logfile>` (output file, written only for open/public buckets), `-t <threads>` (concurrency). Adjust if your installed version differs.

- [ ] **Step 1: Write failing tests**

`tests/unit/test_cloud_assets.py`:
```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/unit/test_cloud_assets.py -v
```

Expected: `ImportError: cannot import name 'collect' from 'apps.cloud_assets.collector'`

- [ ] **Step 3: Implement collector.py**

`apps/cloud_assets/collector.py`:
```python
import logging
import os
import shutil
import subprocess
import tempfile

from django.conf import settings

logger = logging.getLogger(__name__)

_TIMEOUT = 1800  # 30 minutes — cloud_enum probes many permutations


def collect(keywords: list[str]) -> list[str]:
    if not keywords:
        return []

    binary = getattr(settings, "TOOL_CLOUD_ENUM", "cloud_enum")
    if not shutil.which(binary):
        logger.debug("cloud_enum binary not found at %r — skipping", binary)
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as kf:
        kf.write("\n".join(keywords))
        keywords_path = kf.name

    output_path = keywords_path + ".out"

    try:
        cmd = [binary, "-kf", keywords_path, "-l", output_path, "-t", "10"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_TIMEOUT,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            logger.warning("cloud_enum timed out after %ss", _TIMEOUT)
            return []

        if result.returncode != 0:
            logger.warning(
                "cloud_enum exited %s: %s",
                result.returncode,
                (result.stderr or "")[:300],
            )
            return []

        if not os.path.exists(output_path):
            logger.info("[cloud_assets] cloud_enum found no open buckets")
            return []

        with open(output_path) as f:
            raw = f.read()

        if not raw.strip():
            return []

        return [line.strip() for line in raw.splitlines() if line.strip()]

    finally:
        for path in (keywords_path, output_path):
            try:
                os.unlink(path)
            except OSError:
                continue
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/unit/test_cloud_assets.py::TestCollect -v
```

Expected: `7 passed`

- [ ] **Step 5: Commit**

```bash
git add apps/cloud_assets/collector.py tests/unit/test_cloud_assets.py
git commit -m "feat: add cloud_assets collector"
```

---

## Task 3: Analyzer

**Files:**
- Modify: `tests/unit/test_cloud_assets.py` (add TestAnalyze)
- Create: `apps/cloud_assets/analyzer.py`

The analyzer parses each URL to detect provider and bucket name, then builds one `Finding` per URL.

- [ ] **Step 1: Add TestAnalyze to the test file**

Append to `tests/unit/test_cloud_assets.py`:
```python

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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/unit/test_cloud_assets.py::TestAnalyze -v
```

Expected: `ImportError: cannot import name 'analyze' from 'apps.cloud_assets.analyzer'`

- [ ] **Step 3: Implement analyzer.py**

`apps/cloud_assets/analyzer.py`:
```python
import logging
import re

from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)

_AWS_VIRTUAL = re.compile(r"https?://([^.]+)\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com")
_AWS_PATH = re.compile(r"https?://s3(?:\.[a-z0-9-]+)?\.amazonaws\.com/([^/\s]+)")
_AZURE = re.compile(r"https?://([^.]+)\.blob\.core\.windows\.net")
_GCP = re.compile(r"https?://storage\.googleapis\.com/([^/\s]+)")

_PROVIDER_SHORT = {"AWS S3": "aws", "Azure Blob": "azure", "GCP Storage": "gcp"}


def _parse_url(url: str) -> tuple[str, str] | None:
    """Return (provider_label, bucket_name) or None if url is unrecognized."""
    m = _AWS_VIRTUAL.search(url)
    if m:
        return "AWS S3", m.group(1)

    m = _AWS_PATH.search(url)
    if m:
        return "AWS S3", m.group(1)

    m = _AZURE.search(url)
    if m:
        return "Azure Blob", m.group(1)

    m = _GCP.search(url)
    if m:
        return "GCP Storage", m.group(1)

    return None


def analyze(session, urls: list[str]) -> list[Finding]:
    if not urls:
        return []

    seen: set[str] = set()
    findings: list[Finding] = []

    for url in urls:
        url = url.strip()
        if not url or url in seen:
            continue
        seen.add(url)

        parsed = _parse_url(url)
        if parsed is None:
            logger.warning("cloud_assets: unrecognized bucket URL %r — skipping", url)
            continue

        provider, bucket_name = parsed
        short = _PROVIDER_SHORT[provider]

        findings.append(
            Finding(
                session=session,
                source="cloud_assets",
                check_type="open_cloud_bucket",
                severity="high",
                title=f"Public {provider} bucket: {bucket_name}",
                description=(
                    f"The {provider} bucket at {url} is publicly accessible. "
                    f"An unauthenticated attacker can list or read its contents."
                ),
                remediation=(
                    f"Set the bucket ACL to private and disable public access. "
                    f"For AWS: enable Block Public Access on {bucket_name}. "
                    f"Verify with: curl -I {url}"
                ),
                target=url,
                extra={"provider": short, "bucket_name": bucket_name, "url": url},
            )
        )

    return findings
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/unit/test_cloud_assets.py::TestAnalyze -v
```

Expected: `6 passed`

- [ ] **Step 5: Commit**

```bash
git add apps/cloud_assets/analyzer.py tests/unit/test_cloud_assets.py
git commit -m "feat: add cloud_assets analyzer"
```

---

## Task 4: Scanner

**Files:**
- Modify: `tests/unit/test_cloud_assets.py` (add TestScanner)
- Create: `apps/cloud_assets/scanner.py`

The scanner derives keywords from the session's domain string and subdomain rows, calls collect + analyze, bulk-saves findings, and returns the persisted list.

- [ ] **Step 1: Add TestScanner to the test file**

Append to `tests/unit/test_cloud_assets.py`:
```python

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
        # "s3" and "ns" are < 3 chars, filtered out
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/unit/test_cloud_assets.py::TestDeriveKeywords tests/unit/test_cloud_assets.py::TestScanner -v
```

Expected: `ImportError: cannot import name '_derive_keywords' from 'apps.cloud_assets.scanner'`

- [ ] **Step 3: Implement scanner.py**

`apps/cloud_assets/scanner.py`:
```python
import logging

from apps.core.assets.models import Subdomain
from apps.core.findings.models import Finding

from .analyzer import analyze
from .collector import collect

logger = logging.getLogger(__name__)

_MIN_KEYWORD_LEN = 3


def _derive_keywords(domain: str, subdomains: list[str]) -> list[str]:
    apex_label = domain.split(".")[0].lower()
    seen: set[str] = set()
    keywords: list[str] = []

    for label in [apex_label] + [s.split(".")[0].lower() for s in subdomains]:
        if len(label) >= _MIN_KEYWORD_LEN and label not in seen:
            seen.add(label)
            keywords.append(label)

    return keywords


def run_cloud_assets(session) -> list[Finding]:
    domain = session.domain  # CharField: "example.com"
    subdomain_values = list(
        Subdomain.objects.filter(session=session)
        .values_list("subdomain", flat=True)
        .distinct()
    )
    keywords = _derive_keywords(domain, subdomain_values)

    if not keywords:
        logger.info(f"[cloud_assets:{session.id}] no keywords derived — skipping")
        return []

    urls = collect(keywords)
    findings = analyze(session, urls)

    if findings:
        Finding.objects.bulk_create(findings, ignore_conflicts=True)

    saved = list(Finding.objects.filter(session=session, source="cloud_assets"))
    logger.info(f"[cloud_assets:{session.id}] saved {len(saved)} open bucket findings")
    return saved
```

- [ ] **Step 4: Run the full test file**

```bash
uv run pytest tests/unit/test_cloud_assets.py -v
```

Expected: `17 passed`

- [ ] **Step 5: Run the full fast test suite to check for regressions**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -q
```

Expected: all tests pass (count increases by 17).

- [ ] **Step 6: Commit**

```bash
git add apps/cloud_assets/scanner.py tests/unit/test_cloud_assets.py
git commit -m "feat: add cloud_assets scanner and complete test suite"
```

---

## Final Step: Open PR

```bash
gh pr create \
  --title "feat: add cloud_assets tool (AWS S3 + Azure Blob + GCP Storage)" \
  --body "$(cat <<'EOF'
## Summary
- Adds `apps/cloud_assets/` — Phase 4 tool that enumerates publicly accessible cloud storage buckets
- Uses `cloud_enum` (pip: `cloud-enum`) with keywords derived from apex domain + discovered subdomains
- Probes AWS S3, Azure Blob, and GCP Storage; reports each open bucket as a `high` severity Finding
- 17 unit tests covering collector (7), analyzer (6), scanner (4)
- No new models or migrations

## Test plan
- [ ] `uv run pytest tests/unit/test_cloud_assets.py -v` → 20 passed
- [ ] `uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -q` → full suite passes
- [ ] `uv run manage.py check` → no issues
- [ ] Confirm `cloud_enum` appears in workflow tool list at `/api/workflows/tools/`
EOF
)"
```
