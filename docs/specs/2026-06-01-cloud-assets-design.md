# Cloud Assets Tool — Design Spec

**Goal:** Add a `cloud_assets` tool to the OpenEASD pipeline that discovers publicly accessible AWS S3, Azure Blob, and GCP Storage buckets associated with a target domain.

**Architecture:** Standard 5-file tool app (`apps/cloud_assets/`) using the existing collector → analyzer → scanner pattern. Wraps the `cloud_enum` Python binary (installed via pip as a project dependency). Runs at Phase 4 alongside `takeover_check` — both deal with cloud misconfigurations and run in parallel after subdomain enumeration.

**Tech Stack:** Python, `cloud_enum` CLI (`pip install cloud-enum`), Django ORM, `apps/core/findings/Finding` model.

---

## Phase Placement

```
Phase 4  cloud_assets   →  Finding (open S3/Azure/GCP buckets)   ┐ parallel
Phase 4  takeover_check →  Finding (dangling DNS → unclaimed cloud) ┘
```

Runs after Phase 3 (`dnsx`) so the session's `Subdomain` rows are populated and can be used as additional keywords.

---

## tool_meta

```python
tool_meta = {
    "label": "Cloud Assets",
    "runner": "apps.cloud_assets.scanner.run_cloud_assets",
    "phase": 4,
    "phase_group": "Surface Enumeration",
    "requires": ["subfinder"],
    "produces_findings": True,
}
```

---

## Installation

`cloud_enum` is a Python package. Add to `pyproject.toml` `[project.dependencies]`:

```
cloud-enum
```

No Dockerfile binary download required — `uv sync` installs it into the venv and makes `cloud_enum` available on `PATH`.

Binary path configurable via env var: `TOOL_CLOUD_ENUM` (default: `"cloud_enum"`).

---

## Collector (`collector.py`)

**Signature:**
```python
def collect(keywords: list[str]) -> list[str]:
    ...
```

**Behavior:**
1. Write `keywords` to a temp file (one per line).
2. Run:
   ```
   cloud_enum -kf <keywords_file> -o <output_file> --threads 10
   ```
   All three providers enabled (no `--disable-*` flags).
3. Read `<output_file>` — cloud_enum writes one URL per line for each publicly accessible bucket it finds.
4. Return the URL list.

> **Implementation note:** Verify the exact output file format against the installed version of cloud_enum before finalising the parser. The expected format is one bare URL per line (open buckets only), but this should be confirmed against `cloud_enum --help` or the source.

**Failure modes → return `[]`:**
- Binary not found (`shutil.which` returns `None`)
- `subprocess.TimeoutExpired` (30-minute cap)
- Non-zero exit code
- Output file missing or empty

**Keyword derivation** (done in `scanner.py` before calling collect):
- Apex domain label: `example.com` → `example`
- Per resolved subdomain, take the leftmost label: `dev.example.com` → `dev`
- Lowercase, deduplicated, minimum length 3 (filter `ns1`, `mx`, `s3`, etc.)

---

## Analyzer (`analyzer.py`)

**Signature:**
```python
def analyze(session, urls: list[str]) -> list[Finding]:
    ...
```

**Provider detection from URL pattern:**

| URL pattern | Provider label |
|---|---|
| `s3.amazonaws.com/` or `.s3.amazonaws.com` | `AWS S3` |
| `.blob.core.windows.net` | `Azure Blob` |
| `storage.googleapis.com/` | `GCP Storage` |

Unknown patterns are logged and skipped.

**Finding per open bucket:**

| Field | Value |
|---|---|
| `source` | `"cloud_assets"` |
| `check_type` | `"open_cloud_bucket"` |
| `severity` | `"high"` |
| `title` | `"Public {provider} bucket: {bucket_name}"` |
| `description` | `"The {provider} bucket at {url} is publicly accessible. An unauthenticated attacker can list or read its contents."` |
| `remediation` | `"Set the bucket ACL to private and disable public access. For AWS: enable Block Public Access on {bucket_name}. Verify with: curl -I {url}"` |
| `target` | bucket URL |
| `extra` | `{"provider": "aws\|azure\|gcp", "bucket_name": "...", "url": "..."}` |

**Severity rationale:** `high` — consistent with other cloud-misconfiguration findings (takeover, expired TLS). Cannot confirm sensitive data without reading bucket contents, so `critical` would be over-reported.

**Dedup:** `seen` set within the call; skip duplicate URLs.

---

## Scanner (`scanner.py`)

**Signature:**
```python
def run_cloud_assets(session) -> list[Finding]:
    ...
```

**Flow:**
1. Get `domain = session.domain.domain`.
2. Query `Subdomain.objects.filter(session=session).values_list("subdomain", flat=True)`.
3. Derive keywords: apex label + subdomain leftmost labels, deduped, min length 3.
4. If no keywords → return `[]` (no-op log).
5. Call `collect(keywords)`.
6. Call `analyze(session, urls)`.
7. `Finding.objects.bulk_create(findings, ignore_conflicts=True)`.
8. Return `list(Finding.objects.filter(session=session, source="cloud_assets"))`.

---

## Wiring

| File | Change |
|---|---|
| `pyproject.toml` | Add `cloud-enum` to `[project.dependencies]` |
| `openeasd/settings.py` | `TOOL_CLOUD_ENUM = config("TOOL_CLOUD_ENUM", default="cloud_enum")` |
| `openeasd/settings.py` | Add `"apps.cloud_assets"` to `INSTALLED_APPS` after `"apps.takeover_check"` |

No migrations needed — no new models (findings go to `apps/core/findings/Finding`).

---

## Tests (`tests/unit/test_cloud_assets.py`)

**TestCollect** (7 tests):
- Missing binary → `[]`
- Non-zero exit → `[]`
- Timeout → `[]`
- Empty keywords → `[]`
- Output file missing → `[]`
- Happy path AWS URL → returned
- Happy path all-three-provider URLs → all returned

**TestAnalyze** (6 tests):
- Empty URLs → `[]`
- AWS S3 virtual-hosted URL → correct `Finding` fields
- AWS S3 path-style URL → correct `Finding` fields
- Azure Blob URL → correct `Finding` fields
- GCP Storage URL → correct `Finding` fields
- Duplicate URLs → deduped to one finding

**TestScanner** (4 tests):
- No subdomains in session → `[]`, collect not called
- Happy path → findings persisted and returned
- Keywords derived correctly from domain + subdomains (min length filter)
- Short subdomain labels (len < 3) filtered out

---

## Out of Scope

- User-configurable extra keywords (future PR if requested)
- Checking bucket contents or classifying sensitive data
- Private bucket inventory (`info` findings for non-public buckets)
- Azure Container Registry, ECR, or other cloud services beyond object storage
