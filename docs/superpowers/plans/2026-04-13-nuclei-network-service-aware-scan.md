# Nuclei Network: Service-Aware Scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make nuclei_network build its `-tags` flag dynamically from detected port services, and add `-severity critical,high,medium,low` to drop info noise.

**Architecture:** A single `_build_tags(ports)` helper in `collector.py` maps `Port.service` values to nuclei tags via partial case-insensitive matching. The `collect()` function calls it, logs the resolved tags, and passes them to nuclei. No other files change.

**Tech Stack:** Python, nuclei v3.7.1, Django ORM (Port model)

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `apps/nuclei_network/collector.py` | Modify | Add `_build_tags()`, update `collect()` command |
| `tests/unit/test_nuclei_network.py` | Create | Unit tests for tag building and collect() integration |

---

### Task 1: Write failing tests for `_build_tags`

**Files:**
- Create: `tests/unit/test_nuclei_network.py`

- [ ] **Step 1: Create the test file**

```python
"""Unit tests for nuclei_network collector — service-aware tag building."""

import pytest
from unittest.mock import MagicMock, patch, call
from apps.nuclei_network.collector import _build_tags, collect

# ---------------------------------------------------------------------------
# _build_tags tests
# ---------------------------------------------------------------------------

def _port(service):
    p = MagicMock()
    p.service = service
    p.address = "1.2.3.4"
    p.port = 6379
    return p


def test_build_tags_redis():
    ports = [_port("redis")]
    tags = _build_tags(ports)
    assert "redis" in tags
    assert "misconfig" in tags
    assert "exposures" in tags
    assert "default-login" in tags
    assert "cves" in tags


def test_build_tags_ftp():
    ports = [_port("ftp")]
    tags = _build_tags(ports)
    assert "ftp" in tags


def test_build_tags_smtp():
    ports = [_port("smtp")]
    tags = _build_tags(ports)
    assert "smtp" in tags


def test_build_tags_smtps():
    ports = [_port("smtps")]
    tags = _build_tags(ports)
    assert "smtp" in tags


def test_build_tags_postgresql():
    ports = [_port("postgresql")]
    tags = _build_tags(ports)
    assert "postgresql" in tags


def test_build_tags_postgres_variant():
    ports = [_port("postgres")]
    tags = _build_tags(ports)
    assert "postgresql" in tags


def test_build_tags_ssh_skipped():
    """ssh is handled by ssh_checker — must not appear in nuclei_network tags."""
    ports = [_port("ssh")]
    tags = _build_tags(ports)
    assert "ssh" not in tags


def test_build_tags_unknown_service_uses_baseline():
    """Unknown service should fall back to baseline tags only."""
    ports = [_port("unknown-proto")]
    tags = _build_tags(ports)
    assert tags == {"misconfig", "exposures", "default-login", "cves"}


def test_build_tags_empty_service_uses_baseline():
    ports = [_port("")]
    tags = _build_tags(ports)
    assert tags == {"misconfig", "exposures", "default-login", "cves"}


def test_build_tags_multiple_services():
    ports = [_port("redis"), _port("ftp"), _port("mysql")]
    tags = _build_tags(ports)
    assert "redis" in tags
    assert "ftp" in tags
    assert "mysql" in tags


def test_build_tags_case_insensitive():
    ports = [_port("Redis"), _port("FTP"), _port("SMTP")]
    tags = _build_tags(ports)
    assert "redis" in tags
    assert "ftp" in tags
    assert "smtp" in tags


def test_build_tags_microsoft_ds_maps_to_smb():
    ports = [_port("microsoft-ds")]
    tags = _build_tags(ports)
    assert "smb" in tags


def test_build_tags_returns_set():
    ports = [_port("redis"), _port("redis")]
    tags = _build_tags(ports)
    assert isinstance(tags, set)
    assert tags.count("redis") if isinstance(tags, list) else len([t for t in tags if t == "redis"]) == 1


# ---------------------------------------------------------------------------
# collect() integration tests
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_session():
    s = MagicMock()
    s.id = "test-session-id"
    return s


@patch("apps.nuclei_network.collector.subprocess.run")
@patch("apps.nuclei_network.collector.Port")
def test_collect_builds_correct_command(MockPort, mock_run, mock_session):
    port = MagicMock()
    port.address = "1.2.3.4"
    port.port = 6379
    port.service = "redis"
    MockPort.objects.filter.return_value = [port]

    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

    collect(mock_session)

    cmd = mock_run.call_args[0][0]
    assert "-pt" in cmd
    assert "network,ssl" in cmd
    assert "-tags" in cmd
    tags_val = cmd[cmd.index("-tags") + 1]
    assert "redis" in tags_val
    assert "-severity" in cmd
    sev_val = cmd[cmd.index("-severity") + 1]
    assert "critical" in sev_val
    assert "info" not in sev_val


@patch("apps.nuclei_network.collector.subprocess.run")
@patch("apps.nuclei_network.collector.Port")
def test_collect_no_ports_returns_empty(MockPort, mock_run, mock_session):
    MockPort.objects.filter.return_value = []
    result = collect(mock_session)
    assert result == []
    mock_run.assert_not_called()
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
uv run pytest tests/unit/test_nuclei_network.py -v 2>&1 | head -40
```

Expected: `ImportError` or `AttributeError` — `_build_tags` does not exist yet.

---

### Task 2: Implement `_build_tags` and update `collect()`

**Files:**
- Modify: `apps/nuclei_network/collector.py`

- [ ] **Step 1: Replace collector.py with the updated implementation**

```python
"""Nuclei binary execution — data collection layer.

Runs the nuclei binary against non-web ports discovered by naabu/service_detection.
Uses service-aware tag selection: maps Port.service to nuclei template tags so only
relevant templates run per session.
"""

import json
import logging
import os
import subprocess
import tempfile

from django.conf import settings

logger = logging.getLogger(__name__)

BINARY = getattr(settings, "TOOL_NUCLEI", "nuclei")
TIMEOUT = 3600  # 1 hour max per scan

# Baseline tags always included regardless of services found
_BASELINE_TAGS = {"misconfig", "exposures", "default-login", "cves"}

# Maps partial service name (lowercase) → nuclei tag
# ssh is intentionally excluded — handled by ssh_checker
_SERVICE_TAG_MAP = {
    "ftp":           "ftp",
    "smtp":          "smtp",
    "smtps":         "smtp",
    "redis":         "redis",
    "mysql":         "mysql",
    "postgresql":    "postgresql",
    "postgres":      "postgresql",
    "mongodb":       "mongodb",
    "ldap":          "ldap",
    "ldaps":         "ldap",
    "vnc":           "vnc",
    "rdp":           "rdp",
    "elasticsearch": "elasticsearch",
    "memcached":     "memcached",
    "smb":           "smb",
    "microsoft-ds":  "smb",
    "mssql":         "mssql",
    "ms-sql":        "mssql",
    "cassandra":     "cassandra",
    "rabbitmq":      "rabbitmq",
    "amqp":          "rabbitmq",
}


def _build_tags(ports) -> set[str]:
    """
    Build a set of nuclei tags from the services detected on the given ports.

    Performs case-insensitive partial matching against _SERVICE_TAG_MAP.
    Always includes _BASELINE_TAGS. Skips ssh (owned by ssh_checker).
    Falls back to _BASELINE_TAGS only if no services are recognised.
    """
    tags = set(_BASELINE_TAGS)
    for port in ports:
        service = (port.service or "").lower().strip()
        if not service:
            continue
        for key, tag in _SERVICE_TAG_MAP.items():
            if key in service:
                tags.add(tag)
                break
    return tags


def collect(session) -> list[dict]:
    """
    Run nuclei with service-aware network templates against non-web ports.

    Builds IP:port targets from Port objects with is_web=False, derives
    nuclei tags from detected service names, and runs nuclei in JSONL mode.

    Returns list of raw nuclei JSON records (one per finding).
    """
    from apps.core.assets.models import Port

    ports = list(Port.objects.filter(session=session, state="open", is_web=False))
    if not ports:
        logger.info(f"[nuclei_network:{session.id}] No non-web ports to scan")
        return []

    tags = _build_tags(ports)
    targets = sorted(set(f"{p.address}:{p.port}" for p in ports))

    logger.info(
        f"[nuclei_network:{session.id}] Scanning {len(targets)} non-web targets "
        f"with tags={sorted(tags)}"
    )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        tmp = f.name

    cmd = [
        BINARY, "-list", tmp,
        "-pt", "network,ssl",
        "-tags", ",".join(sorted(tags)),
        "-severity", "critical,high,medium,low",
        "-jsonl", "-silent", "-no-color",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
    except FileNotFoundError:
        logger.error(f"[nuclei_network:{session.id}] Binary not found: {BINARY}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[nuclei_network:{session.id}] Timed out after {TIMEOUT}s")
        return []
    finally:
        os.unlink(tmp)

    if result.returncode != 0 and result.stderr:
        logger.warning(f"[nuclei_network:{session.id}] stderr: {result.stderr[:500]}")

    records = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            logger.debug(f"[nuclei_network:{session.id}] Skipping non-JSON line: {line[:100]}")

    logger.info(f"[nuclei_network:{session.id}] Parsed {len(records)} raw findings")
    return records
```

- [ ] **Step 2: Run all tests and confirm they pass**

```bash
uv run pytest tests/unit/test_nuclei_network.py -v
```

Expected: All tests PASS.

- [ ] **Step 3: Run full fast test suite to confirm no regressions**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -q
```

Expected: All pass, 0 failures.

- [ ] **Step 4: Commit**

```bash
git add apps/nuclei_network/collector.py tests/unit/test_nuclei_network.py
git commit -m "feat: nuclei_network service-aware tag selection + severity filter"
```
