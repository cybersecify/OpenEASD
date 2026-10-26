# Finding Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-probe each medium-or-higher finding at scan finalize and label it `verified` / `inconclusive` / `unverified`, carrying the verdict onto the enduring `Issue` and surfacing it in the API + report.

**Architecture:** A new engine package (`apps/core/engine/verification/`) runs a deterministic per-tool re-probe over medium+ findings, gated by a setting and (for active tools) by `DomainAuthorization`. Tools opt in by registering a `verifier` in `tool_meta` (Approach A). An optional AI adjudication layer annotates — but never overrides — the deterministic verdict. The verdict mirrors onto `Issue` via the existing finalize rollup.

**Tech Stack:** Django 5.2, Django-Ninja, PostgreSQL, DBOS, pytest + pytest-django (real postgres service DB), `uv run` for all commands.

**Spec:** `docs/specs/2026-09-15-finding-verification.md`

## Global Constraints

- Use `uv run python` / `uv run manage.py` / `uv run pytest` for everything — never bare `python`.
- GitHub Flow: branch `feat/finding-verification` off `main`; never commit to `main`. Commit prefixes per CLAUDE.md (`feat:`/`test:`/`docs:`). Commit messages end with the session attribution trailer (see CLAUDE.md / session reminder); no `Co-Authored-By: Claude` beyond that trailer.
- Coverage gate ≥ 80% must hold; run `uv run pytest tests/ --ignore=tests/unit/test_domain_security.py` for fast runs.
- **Byte-identical invariant:** with `FINDING_VERIFICATION_ENABLED=False`, `_finalize_session` must behave exactly as before this feature. Guard it with a test.
- **AI invariants (unchanged):** the AI adjudication layer must be a no-op when `guard.is_ai_active()` is False, must never write `Finding.status` or `Finding.verification_status`, and every Cloudflare call must still produce exactly one metadata-only `AIInvocation` row.
- **Tool isolation:** a tool's `verify.py` imports only from `apps.core.data.*` and stdlib/its own collector — never another tool.
- **Fail-graceful:** no verification error may fail a scan; a verifier that raises ⇒ `inconclusive`.
- Verdict string values are exactly: `"unverified"`, `"verified"`, `"inconclusive"`.

---

### Task 1: Verdict dataclass + verification package skeleton + settings

**Files:**
- Create: `apps/core/engine/verification/__init__.py`
- Create: `apps/core/engine/verification/verdict.py`
- Modify: `openeasd/settings/base.py` (add two settings near the other scan tunables)
- Test: `tests/unit/test_verification_verdict.py`

**Interfaces:**
- Produces: `Verdict` dataclass — `Verdict(verdict: str, evidence: str = "", detail: str = "")`, with class constants `Verdict.VERIFIED = "verified"` and `Verdict.INCONCLUSIVE = "inconclusive"`; module constants `UNVERIFIED = "unverified"`, `VERIFICATION_STATUSES = ("unverified", "verified", "inconclusive")`.
- Produces settings: `FINDING_VERIFICATION_ENABLED: bool` (default `True`), `FINDING_VERIFICATION_MIN_SEVERITY: str` (default `"medium"`).

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_verification_verdict.py
from apps.core.engine.verification.verdict import Verdict, UNVERIFIED, VERIFICATION_STATUSES


def test_verdict_constructs_with_defaults():
    v = Verdict(Verdict.VERIFIED)
    assert v.verdict == "verified"
    assert v.evidence == "" and v.detail == ""


def test_verdict_carries_evidence_and_detail():
    v = Verdict(Verdict.INCONCLUSIVE, evidence="HTTP 000", detail="unreachable")
    assert v.verdict == "inconclusive"
    assert v.evidence == "HTTP 000" and v.detail == "unreachable"


def test_status_vocabulary_is_closed():
    assert UNVERIFIED == "unverified"
    assert set(VERIFICATION_STATUSES) == {"unverified", "verified", "inconclusive"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_verification_verdict.py -v`
Expected: FAIL — `ModuleNotFoundError: apps.core.engine.verification.verdict`

- [ ] **Step 3: Write minimal implementation**

```python
# apps/core/engine/verification/__init__.py
```
(empty file)

```python
# apps/core/engine/verification/verdict.py
"""Verdict value object for finding verification.

A verifier returns a Verdict; the orchestrator maps it onto the Finding's
verification fields. Deterministic layer only — the AI layer never constructs one.
"""
from dataclasses import dataclass

UNVERIFIED = "unverified"
VERIFICATION_STATUSES = ("unverified", "verified", "inconclusive")


@dataclass(frozen=True)
class Verdict:
    VERIFIED = "verified"
    INCONCLUSIVE = "inconclusive"

    verdict: str
    evidence: str = ""
    detail: str = ""
```

Then add to `openeasd/settings/base.py` (near the other `SCAN_*` / profile tunables):

```python
# Finding verification — deterministic re-probe of medium+ findings at finalize.
FINDING_VERIFICATION_ENABLED = config("FINDING_VERIFICATION_ENABLED", default=True, cast=bool)
FINDING_VERIFICATION_MIN_SEVERITY = config("FINDING_VERIFICATION_MIN_SEVERITY", default="medium")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_verification_verdict.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add apps/core/engine/verification/ tests/unit/test_verification_verdict.py openeasd/settings/base.py
git commit -m "feat: add Verdict value object + verification settings"
```

---

### Task 2: Registry — `get_tool_verifiers()`

**Files:**
- Modify: `apps/core/engine/workflows/registry.py`
- Test: `tests/unit/test_verification_registry.py`

**Interfaces:**
- Consumes: `tool_meta["verifier"]` — an optional dotted path string on any `AppConfig`.
- Produces: `get_tool_verifiers() -> dict[str, Callable]` — maps `source` (tool label) → the imported `verify_finding` callable, only for tools that declare `"verifier"`. Mirrors the existing `get_tool_runners()`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_verification_registry.py
from apps.core.engine.workflows import registry as R


def test_get_tool_verifiers_returns_callables_for_declaring_tools():
    verifiers = R.get_tool_verifiers()
    assert isinstance(verifiers, dict)
    # web_checker declares a verifier (added in a later task); until then this
    # dict may be empty. The contract under test: every value is callable, and
    # every key is a known tool source.
    runners = R.get_tool_runners()
    for source, fn in verifiers.items():
        assert source in runners
        assert callable(fn)


def test_get_tool_verifiers_skips_tools_without_the_key():
    # subfinder has no verifier -> must not appear.
    assert "subfinder" not in R.get_tool_verifiers()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_verification_registry.py -v`
Expected: FAIL — `AttributeError: module ... has no attribute 'get_tool_verifiers'`

- [ ] **Step 3: Write minimal implementation**

In `apps/core/engine/workflows/registry.py`, mirror the existing runner-resolution pattern (find `get_tool_runners` and copy its `import_string`/`tool_meta` iteration shape):

```python
from django.utils.module_loading import import_string  # if not already imported


def get_tool_verifiers():
    """source -> verify_finding callable, for tools that declare tool_meta['verifier'].

    Optional per tool: a tool without a verifier is honestly left un-reprobed.
    """
    verifiers = {}
    for app_config in _iter_tool_apps():  # reuse whatever helper get_tool_runners uses
        meta = getattr(app_config, "tool_meta", None)
        if not meta:
            continue
        path = meta.get("verifier")
        if not path:
            continue
        verifiers[app_config.label] = import_string(path)
    return verifiers
```

Note: match the exact iteration helper `get_tool_runners()` uses in this file (it already enumerates tool apps + reads `tool_meta`). Do not introduce a second enumeration mechanism.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_verification_registry.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add apps/core/engine/workflows/registry.py tests/unit/test_verification_registry.py
git commit -m "feat: registry get_tool_verifiers() (Approach A)"
```

---

### Task 3: Finding model — verification fields + migration

**Files:**
- Modify: `apps/core/data/findings/models.py`
- Create: `apps/core/data/findings/migrations/0013_finding_verification.py` (confirm the next number with `ls apps/core/data/findings/migrations/`)
- Test: `tests/unit/test_verification_model.py`

**Interfaces:**
- Produces: `Finding.verification_status` (CharField, default `"unverified"`, `db_index=True`), `Finding.verified_at` (DateTimeField, null=True, blank=True). Verification detail is stored in the existing `Finding.extra["verification"]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_verification_model.py
import pytest


@pytest.mark.django_db
def test_finding_defaults_to_unverified():
    from apps.core.engine.scans.models import ScanSession
    from apps.core.data.findings.models import Finding
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    f = Finding.objects.create(session=s, source="web_checker", check_type="missing_header",
                               severity="medium", title="Missing CSP", target="example.com")
    assert f.verification_status == "unverified"
    assert f.verified_at is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_verification_model.py -v`
Expected: FAIL — `AttributeError: 'Finding' object has no attribute 'verification_status'`

- [ ] **Step 3: Write minimal implementation**

In `apps/core/data/findings/models.py`, after the `status`/`resolved_at` lifecycle block:

```python
    # Verification (deterministic re-probe at finalize; see engine/verification).
    verification_status = models.CharField(
        max_length=20, default="unverified", db_index=True
    )
    verified_at = models.DateTimeField(null=True, blank=True)
```

Generate the migration:

```bash
uv run manage.py makemigrations findings
```
Confirm it creates `verification_status` + `verified_at` only (no unrelated changes).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_verification_model.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add apps/core/data/findings/models.py apps/core/data/findings/migrations/
git commit -m "feat: Finding.verification_status + verified_at"
```

---

### Task 4: Issue model — verification_status + rollup mirror

**Files:**
- Modify: `apps/core/data/issues/models.py`
- Create: `apps/core/data/issues/migrations/0006_issue_verification_status.py` (confirm next number)
- Modify: `apps/core/data/issues/rollup.py`
- Test: `tests/unit/test_issue_register.py` (add a case)

**Interfaces:**
- Consumes: `Finding.verification_status` (Task 3).
- Produces: `Issue.verification_status` (CharField, default `"unverified"`, `db_index=True`), mirrored from the finding by `rollup_session_issues`.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/unit/test_issue_register.py inside TestIssueRegister
    def test_verification_status_mirrors_onto_issue(self):
        from apps.core.data.issues.models import Issue
        dom, s1 = self._domain_and_session()
        f = self._finding(s1)
        f.verification_status = "verified"
        f.save(update_fields=["verification_status"])
        self._rollup(s1)
        assert Issue.objects.get(domain=dom).verification_status == "verified"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_issue_register.py::TestIssueRegister::test_verification_status_mirrors_onto_issue -v`
Expected: FAIL — `AttributeError: ... 'verification_status'`

- [ ] **Step 3: Write minimal implementation**

In `apps/core/data/issues/models.py`, after the triage block (`assigned_to`/`resolution_note`):

```python
    # Latest occurrence's verification verdict, mirrored by the rollup (display).
    verification_status = models.CharField(
        max_length=20, default="unverified", db_index=True
    )
```

Migration:

```bash
uv run manage.py makemigrations issues
```

In `apps/core/data/issues/rollup.py`, set it on **both** the create-defaults and the update path. In the `get_or_create(defaults={...})` add `"verification_status": f.verification_status,`. In the `if not created:` block add `issue.verification_status = f.verification_status` and append `"verification_status"` to that block's `save(update_fields=[...])` list.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_issue_register.py -v`
Expected: PASS (all existing + the new one)

- [ ] **Step 5: Commit**

```bash
git add apps/core/data/issues/ tests/unit/test_issue_register.py
git commit -m "feat: Issue.verification_status mirrored by the rollup"
```

---

### Task 5: Orchestrator — `verify_session`

**Files:**
- Create: `apps/core/engine/verification/verifier.py`
- Test: `tests/unit/test_verification_orchestrator.py`

**Interfaces:**
- Consumes: `Verdict` (Task 1), `get_tool_verifiers()` (Task 2), `Finding.verification_status`/`verified_at` (Task 3), `registry.get_tool_active()`, `apps.core.constants.SEVERITY_RANK`.
- Produces: `verify_session(session, *, threshold=None) -> None`. Also `_authorized_for(session) -> bool` (module-private) and `_meets_threshold(sev, threshold) -> bool`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_verification_orchestrator.py
import pytest
from unittest.mock import patch
from apps.core.engine.verification.verdict import Verdict


def _session(status="completed"):
    from apps.core.engine.scans.models import ScanSession
    return ScanSession.objects.create(domain="example.com", scan_type="full", status=status)


def _finding(s, source="web_checker", sev="high", **kw):
    from apps.core.data.findings.models import Finding
    return Finding.objects.create(session=s, source=source, check_type="missing_header",
                                  severity=sev, title="t", target="example.com", **kw)


@pytest.mark.django_db
def test_below_threshold_left_unverified():
    from apps.core.engine.verification.verifier import verify_session
    s = _session(); f = _finding(s, sev="low")
    with patch("apps.core.engine.verification.verifier.get_tool_verifiers",
               return_value={"web_checker": lambda finding: Verdict(Verdict.VERIFIED)}):
        verify_session(s, threshold="medium")
    f.refresh_from_db()
    assert f.verification_status == "unverified"


@pytest.mark.django_db
def test_passive_tool_verified_writes_verdict_and_evidence():
    from apps.core.engine.verification.verifier import verify_session
    s = _session(); f = _finding(s, source="breach_check", sev="high")
    v = Verdict(Verdict.VERIFIED, evidence="still 3 breaches", detail="XposedOrNot")
    with patch("apps.core.engine.verification.verifier.get_tool_verifiers",
               return_value={"breach_check": lambda finding: v}):
        verify_session(s, threshold="medium")
    f.refresh_from_db()
    assert f.verification_status == "verified"
    assert f.verified_at is not None
    assert f.extra["verification"]["evidence"] == "still 3 breaches"
    assert f.extra["verification"]["method"] == "reprobe"


@pytest.mark.django_db
def test_active_tool_without_authorization_is_inconclusive_no_call():
    from apps.core.engine.verification.verifier import verify_session
    s = _session(); f = _finding(s, source="nuclei", sev="high")  # nuclei is active
    called = {"n": 0}
    def _verifier(finding):
        called["n"] += 1
        return Verdict(Verdict.VERIFIED)
    with patch("apps.core.engine.verification.verifier.get_tool_verifiers",
               return_value={"nuclei": _verifier}), \
         patch("apps.core.engine.verification.verifier._authorized_for", return_value=False):
        verify_session(s, threshold="medium")
    f.refresh_from_db()
    assert f.verification_status == "inconclusive"
    assert called["n"] == 0  # never re-probed the target without authorization


@pytest.mark.django_db
def test_verifier_exception_is_inconclusive_and_scan_unaffected():
    from apps.core.engine.verification.verifier import verify_session
    s = _session(); f = _finding(s, source="breach_check", sev="high")
    def _boom(finding):
        raise RuntimeError("network down")
    with patch("apps.core.engine.verification.verifier.get_tool_verifiers",
               return_value={"breach_check": _boom}):
        verify_session(s, threshold="medium")  # must not raise
    f.refresh_from_db()
    assert f.verification_status == "inconclusive"


@pytest.mark.django_db
def test_tool_without_verifier_stays_unverified():
    from apps.core.engine.verification.verifier import verify_session
    s = _session(); f = _finding(s, source="subfinder", sev="high")
    with patch("apps.core.engine.verification.verifier.get_tool_verifiers", return_value={}):
        verify_session(s, threshold="medium")
    f.refresh_from_db()
    assert f.verification_status == "unverified"


@pytest.mark.django_db
def test_idempotent_rerun_overwrites_not_appends():
    from apps.core.engine.verification.verifier import verify_session
    s = _session(); f = _finding(s, source="breach_check", sev="high")
    with patch("apps.core.engine.verification.verifier.get_tool_verifiers",
               return_value={"breach_check": lambda finding: Verdict(Verdict.VERIFIED, evidence="a")}):
        verify_session(s, threshold="medium")
    with patch("apps.core.engine.verification.verifier.get_tool_verifiers",
               return_value={"breach_check": lambda finding: Verdict(Verdict.INCONCLUSIVE, evidence="b")}):
        verify_session(s, threshold="medium")
    f.refresh_from_db()
    assert f.verification_status == "inconclusive"
    assert f.extra["verification"]["evidence"] == "b"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_verification_orchestrator.py -v`
Expected: FAIL — `ModuleNotFoundError: ...verifier`

- [ ] **Step 3: Write minimal implementation**

```python
# apps/core/engine/verification/verifier.py
"""Deterministic finding-verification orchestrator.

Runs at scan finalize (before the issue rollup). Re-probes medium+ findings via
each tool's registered verifier; active re-probes require DomainAuthorization.
Fail-graceful and idempotent. See docs/specs/2026-09-15-finding-verification.md.
"""
import logging

from django.conf import settings
from django.utils import timezone

from apps.core.constants import SEVERITY_RANK
from apps.core.engine.workflows.registry import get_tool_active, get_tool_verifiers

from .verdict import Verdict

logger = logging.getLogger(__name__)


def _meets_threshold(severity: str, threshold: str) -> bool:
    return SEVERITY_RANK.get(severity, -1) >= SEVERITY_RANK.get(threshold, 99)


def _authorized_for(session) -> bool:
    """True if the session's domain has an active DomainAuthorization.

    Mirror the exact query the scan-entry gate uses in
    apps/core/engine/scans/api.py (search 'DomainAuthorization'); reuse that
    lookup rather than re-deriving the field names.
    """
    from apps.core.data.domains.models import Domain, DomainAuthorization  # adjust to actual location
    dom = Domain.objects.filter(name=session.domain).first()
    if dom is None:
        return False
    return DomainAuthorization.objects.filter(
        domain=dom, is_active=True, authorization__isnull=False
    ).exists()


def _apply(finding, verdict: Verdict) -> None:
    finding.verification_status = verdict.verdict
    finding.verified_at = timezone.now() if verdict.verdict == Verdict.VERIFIED else None
    extra = dict(finding.extra or {})
    extra["verification"] = {
        "method": "reprobe",
        "verdict": verdict.verdict,
        "checked_at": timezone.now().isoformat(),
        "evidence": verdict.evidence,
        "detail": verdict.detail,
    }
    finding.extra = extra
    finding.save(update_fields=["verification_status", "verified_at", "extra"])


def verify_session(session, *, threshold: str | None = None) -> None:
    threshold = threshold or getattr(settings, "FINDING_VERIFICATION_MIN_SEVERITY", "medium")
    verifiers = get_tool_verifiers()
    active = get_tool_active()
    authorized = None  # computed lazily only if an active tool needs it

    qs = session.findings.exclude(source="scan_coverage")
    n_verified = n_inconclusive = 0
    for f in qs:
        if not _meets_threshold(f.severity, threshold):
            continue
        verifier = verifiers.get(f.source)
        if verifier is None:
            continue  # honestly unverified — no re-prober for this tool
        if active.get(f.source, True):  # active tools need authorization
            if authorized is None:
                authorized = _authorized_for(session)
            if not authorized:
                _apply(f, Verdict(Verdict.INCONCLUSIVE,
                                  detail="verification skipped: no authorization"))
                n_inconclusive += 1
                continue
        try:
            verdict = verifier(f)
        except Exception:  # noqa: BLE001 — fail-graceful; a verifier never fails a scan
            logger.exception("[verify:%s] verifier for %s raised", session.id, f.source)
            verdict = Verdict(Verdict.INCONCLUSIVE, detail="verifier error")
        _apply(f, verdict)
        if verdict.verdict == Verdict.VERIFIED:
            n_verified += 1
        else:
            n_inconclusive += 1

    logger.info("[verify:%s] %d verified / %d inconclusive (threshold=%s)",
                session.id, n_verified, n_inconclusive, threshold)
```

Note: if `get_tool_active` is not already exported by the registry, add it there mirroring `get_tool_choices` (reads `tool_meta.get("active", True)`); CLAUDE.md states it exists.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_verification_orchestrator.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add apps/core/engine/verification/verifier.py tests/unit/test_verification_orchestrator.py
git commit -m "feat: verify_session orchestrator (severity + auth gated, fail-graceful)"
```

---

### Task 6: Pipeline seam — run verification at finalize

**Files:**
- Modify: `apps/core/engine/scans/pipeline.py` (`_finalize_session`)
- Test: `tests/unit/test_verification_pipeline.py`

**Interfaces:**
- Consumes: `verify_session` (Task 5).
- Produces: verification runs after the asset rollup and **before** the issue rollup, gated by `settings.FINDING_VERIFICATION_ENABLED`, fail-graceful.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_verification_pipeline.py
import pytest
from unittest.mock import patch


@pytest.mark.django_db
def test_finalize_calls_verify_before_issue_rollup(settings):
    settings.FINDING_VERIFICATION_ENABLED = True
    from apps.core.engine.scans import pipeline
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="running")
    order = []
    with patch.object(pipeline, "verify_session", side_effect=lambda *a, **k: order.append("verify")), \
         patch("apps.core.data.issues.rollup.rollup_session_issues", side_effect=lambda *a, **k: order.append("issues")):
        pipeline._finalize_session(s)
    assert order == ["verify", "issues"]


@pytest.mark.django_db
def test_finalize_skips_verify_when_disabled(settings):
    settings.FINDING_VERIFICATION_ENABLED = False
    from apps.core.engine.scans import pipeline
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="running")
    with patch.object(pipeline, "verify_session") as mock_verify:
        pipeline._finalize_session(s)
    mock_verify.assert_not_called()


@pytest.mark.django_db
def test_verify_error_does_not_fail_finalize(settings):
    settings.FINDING_VERIFICATION_ENABLED = True
    from apps.core.engine.scans import pipeline
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="running")
    with patch.object(pipeline, "verify_session", side_effect=RuntimeError("boom")):
        pipeline._finalize_session(s)  # must not raise
    s.refresh_from_db()
    assert s.status in ("completed", "partial")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_verification_pipeline.py -v`
Expected: FAIL — `verify_session` not importable in `pipeline` / order assertion fails

- [ ] **Step 3: Write minimal implementation**

In `apps/core/engine/scans/pipeline.py`, add a module-level import so tests can patch `pipeline.verify_session`:

```python
from apps.core.engine.verification.verifier import verify_session
```

In `_finalize_session`, between the asset-inventory rollup block and the issue-register rollup block, insert:

```python
    # Deterministic finding verification — re-probe medium+ findings before the
    # issue rollup so the verdict mirrors onto the Issue. Gated + fail-graceful.
    if getattr(settings, "FINDING_VERIFICATION_ENABLED", True):
        try:
            verify_session(session)
        except Exception:  # noqa: BLE001
            logger.exception("[%s] verification failed — scan unaffected", session.id)
```

(`settings` is already imported in pipeline.py; confirm and add `from django.conf import settings` if not.)

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_verification_pipeline.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add apps/core/engine/scans/pipeline.py tests/unit/test_verification_pipeline.py
git commit -m "feat: run finding verification at finalize (gated, before issue rollup)"
```

---

### Task 7: Seed verifier — `web_checker` (establishes the verify.py pattern)

**Files:**
- Create: `apps/web_checker/verify.py`
- Modify: `apps/web_checker/apps.py` (add `"verifier"` to `tool_meta`)
- Test: `tests/unit/test_web_checker_verify.py`

**Interfaces:**
- Consumes: `Verdict`; the finding's `check_type`, `target`, `url`, `extra`.
- Produces: `verify_finding(finding) -> Verdict`. Registered as `tool_meta["verifier"] = "apps.web_checker.verify.verify_finding"`.

**Pattern (all seed verifiers follow this):** re-issue only the one check the finding represents; return `Verdict(VERIFIED, evidence=...)` if the condition still holds, `Verdict(INCONCLUSIVE, detail=...)` if it no longer reproduces or the probe fails. Reuse the tool's own `collector`/`analyzer` helpers; never import another tool.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_web_checker_verify.py
import pytest
from unittest.mock import patch


def _finding(check_type="missing_header", target="https://example.com", extra=None):
    from apps.core.data.findings.models import Finding
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    return Finding.objects.create(session=s, source="web_checker", check_type=check_type,
                                  severity="medium", title="Missing CSP", target=target,
                                  extra=extra or {"header": "Content-Security-Policy"})


@pytest.mark.django_db
def test_missing_header_still_missing_is_verified():
    from apps.web_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.web_checker.verify._fetch_headers", return_value={"server": "nginx"}):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED
    assert "Content-Security-Policy" in v.evidence


@pytest.mark.django_db
def test_missing_header_now_present_is_inconclusive():
    from apps.web_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.web_checker.verify._fetch_headers",
               return_value={"content-security-policy": "default-src 'self'"}):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_fetch_failure_is_inconclusive():
    from apps.web_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.web_checker.verify._fetch_headers", side_effect=OSError("timeout")):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_web_checker_verify.py -v`
Expected: FAIL — `ModuleNotFoundError: apps.web_checker.verify`

- [ ] **Step 3: Write minimal implementation**

```python
# apps/web_checker/verify.py
"""Re-probe verifier for web_checker findings (headers/cookies/CORS/security.txt).

Re-fetches the target's response headers and checks whether the specific gap the
finding recorded still holds. Active (touches the target) -> gated upstream by
DomainAuthorization in verify_session.
"""
import requests
from django.conf import settings

from apps.core.engine.verification.verdict import Verdict

_TIMEOUT = 10


def _fetch_headers(url: str) -> dict:
    resp = requests.get(
        url, timeout=_TIMEOUT, allow_redirects=True,
        headers={"User-Agent": getattr(settings, "OPENEASD_USER_AGENT", "OpenEASD")},
    )
    return {k.lower(): v for k, v in resp.headers.items()}


def verify_finding(finding) -> Verdict:
    url = finding.target if finding.target.startswith("http") else f"https://{finding.target}"
    header = (finding.extra or {}).get("header", "")
    try:
        headers = _fetch_headers(url)
    except Exception as exc:  # noqa: BLE001
        return Verdict(Verdict.INCONCLUSIVE, detail=f"fetch failed: {exc}")

    # A "missing header" finding is verified only if it is STILL missing.
    if finding.check_type == "missing_header" and header:
        if header.lower() in headers:
            return Verdict(Verdict.INCONCLUSIVE,
                           detail=f"{header} now present", evidence=headers.get(header.lower(), ""))
        return Verdict(Verdict.VERIFIED, evidence=f"{header} still absent (headers: {sorted(headers)[:8]})")

    # Other check_types: no specific re-probe rule yet -> honest inconclusive.
    return Verdict(Verdict.INCONCLUSIVE, detail=f"no re-probe rule for {finding.check_type}")
```

Add to `apps/web_checker/apps.py` `tool_meta`:

```python
        "verifier": "apps.web_checker.verify.verify_finding",
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_web_checker_verify.py tests/unit/test_verification_registry.py -v`
Expected: PASS (web_checker now appears in `get_tool_verifiers()`)

- [ ] **Step 5: Commit**

```bash
git add apps/web_checker/verify.py apps/web_checker/apps.py tests/unit/test_web_checker_verify.py
git commit -m "feat: web_checker re-probe verifier"
```

---

### Task 8: Seed verifier — `tls_checker`

**Files:**
- Create: `apps/tls_checker/verify.py`
- Modify: `apps/tls_checker/apps.py` (`tool_meta["verifier"]`)
- Test: `tests/unit/test_tls_checker_verify.py`

**Interfaces:** Produces `verify_finding(finding) -> Verdict`; registered `"apps.tls_checker.verify.verify_finding"`.

**Re-probe rule:** re-open a TLS connection to `finding.target` (host:port) and re-read protocol/cipher/expiry. Verified if the weak condition recorded in `finding.extra` (e.g. `extra["protocol"]` deprecated, `extra["cipher"]` weak, cert expired/expiring) still holds; inconclusive if the connection fails or the weakness is gone. Reuse `apps/tls_checker/collector.py` connection helpers.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_tls_checker_verify.py
import pytest
from unittest.mock import patch


def _finding(check_type="weak_protocol", target="example.com:443", extra=None):
    from apps.core.data.findings.models import Finding
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    return Finding.objects.create(session=s, source="tls_checker", check_type=check_type,
                                  severity="high", title="TLS 1.0 enabled", target=target,
                                  extra=extra or {"protocol": "TLSv1.0"})


@pytest.mark.django_db
def test_weak_protocol_still_offered_is_verified():
    from apps.tls_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.tls_checker.verify._probe_protocols", return_value={"TLSv1.0", "TLSv1.2"}):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED


@pytest.mark.django_db
def test_weak_protocol_no_longer_offered_is_inconclusive():
    from apps.tls_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.tls_checker.verify._probe_protocols", return_value={"TLSv1.2", "TLSv1.3"}):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_connection_failure_is_inconclusive():
    from apps.tls_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.tls_checker.verify._probe_protocols", side_effect=OSError("refused")):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_tls_checker_verify.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
# apps/tls_checker/verify.py
"""Re-probe verifier for tls_checker findings."""
import socket
import ssl

from apps.core.engine.verification.verdict import Verdict

_TIMEOUT = 10
_PROTO_FLAGS = {
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


def _split_target(target: str):
    host, _, port = target.partition(":")
    return host, int(port or 443)


def _probe_protocols(host: str, port: int) -> set:
    """Return the set of TLS protocol names the host still accepts."""
    offered = set()
    for name, ver in _PROTO_FLAGS.items():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ver
            ctx.maximum_version = ver
        except ValueError:
            continue
        try:
            with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    offered.add(name)
        except (ssl.SSLError, OSError):
            continue
    return offered


def verify_finding(finding) -> Verdict:
    host, port = _split_target(finding.target)
    weak = (finding.extra or {}).get("protocol")
    try:
        offered = _probe_protocols(host, port)
    except Exception as exc:  # noqa: BLE001
        return Verdict(Verdict.INCONCLUSIVE, detail=f"probe failed: {exc}")
    if not offered:
        return Verdict(Verdict.INCONCLUSIVE, detail="no protocols negotiated")
    if weak and weak in offered:
        return Verdict(Verdict.VERIFIED, evidence=f"{weak} still offered ({sorted(offered)})")
    return Verdict(Verdict.INCONCLUSIVE,
                   detail=f"{weak} no longer offered", evidence=str(sorted(offered)))
```

Add `"verifier": "apps.tls_checker.verify.verify_finding"` to `apps/tls_checker/apps.py` `tool_meta`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_tls_checker_verify.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add apps/tls_checker/verify.py apps/tls_checker/apps.py tests/unit/test_tls_checker_verify.py
git commit -m "feat: tls_checker re-probe verifier"
```

---

### Task 9: Seed verifier — `ssh_checker`

**Files:**
- Create: `apps/ssh_checker/verify.py`
- Modify: `apps/ssh_checker/apps.py` (`tool_meta["verifier"]`)
- Test: `tests/unit/test_ssh_checker_verify.py`

**Interfaces:** Produces `verify_finding(finding) -> Verdict`; registered `"apps.ssh_checker.verify.verify_finding"`.

**Re-probe rule:** re-read the SSH server's KEX/cipher/MAC/auth banner for `finding.target` (host:port) using the tool's existing `collector` probe. Verified if the specific weak algorithm/config in `finding.extra` is still offered; inconclusive on connection failure or if the weakness is gone.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_ssh_checker_verify.py
import pytest
from unittest.mock import patch


def _finding(check_type="weak_kex", target="example.com:22", extra=None):
    from apps.core.data.findings.models import Finding
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    return Finding.objects.create(session=s, source="ssh_checker", check_type=check_type,
                                  severity="medium", title="Weak KEX", target=target,
                                  extra=extra or {"algorithm": "diffie-hellman-group1-sha1"})


@pytest.mark.django_db
def test_weak_algo_still_offered_is_verified():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.ssh_checker.verify._probe_algorithms",
               return_value={"kex": ["diffie-hellman-group1-sha1", "curve25519-sha256"]}):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED


@pytest.mark.django_db
def test_weak_algo_gone_is_inconclusive():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.ssh_checker.verify._probe_algorithms",
               return_value={"kex": ["curve25519-sha256"]}):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_connect_failure_is_inconclusive():
    from apps.ssh_checker.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.ssh_checker.verify._probe_algorithms", side_effect=OSError("refused")):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_ssh_checker_verify.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
# apps/ssh_checker/verify.py
"""Re-probe verifier for ssh_checker findings — re-reads the server's offered
KEX/cipher/MAC algorithms and checks whether the flagged weak one is still there.
"""
from apps.core.engine.verification.verdict import Verdict

# Reuse the tool's own algorithm probe. If ssh_checker/collector.py exposes a
# helper that returns offered algorithms, import and wrap it here instead of
# re-implementing. This thin wrapper isolates it for test patching.
def _probe_algorithms(host: str, port: int) -> dict:
    from apps.ssh_checker import collector
    return collector.probe_algorithms(host, port)  # adjust to the collector's real fn name


def _split_target(target: str):
    host, _, port = target.partition(":")
    return host, int(port or 22)


def verify_finding(finding) -> Verdict:
    host, port = _split_target(finding.target)
    algo = (finding.extra or {}).get("algorithm", "")
    try:
        offered = _probe_algorithms(host, port)
    except Exception as exc:  # noqa: BLE001
        return Verdict(Verdict.INCONCLUSIVE, detail=f"probe failed: {exc}")
    all_algos = {a for group in offered.values() for a in group}
    if algo and algo in all_algos:
        return Verdict(Verdict.VERIFIED, evidence=f"{algo} still offered")
    return Verdict(Verdict.INCONCLUSIVE, detail=f"{algo} no longer offered")
```

Note: confirm the real helper name in `apps/ssh_checker/collector.py`; if the collector's probe isn't factored as a reusable function, extract one in this task (small refactor) so `_probe_algorithms` can call it. Add `"verifier"` to `apps/ssh_checker/apps.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_ssh_checker_verify.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add apps/ssh_checker/verify.py apps/ssh_checker/apps.py tests/unit/test_ssh_checker_verify.py
git commit -m "feat: ssh_checker re-probe verifier"
```

---

### Task 10: Seed verifier — `nuclei`

**Files:**
- Create: `apps/nuclei/verify.py`
- Modify: `apps/nuclei/apps.py` (`tool_meta["verifier"]`)
- Test: `tests/unit/test_nuclei_verify.py`

**Interfaces:** Produces `verify_finding(finding) -> Verdict`; registered `"apps.nuclei.verify.verify_finding"`.

**Re-probe rule:** re-run nuclei with the single matched template (`finding.extra["template_id"]`) against `finding.url`/`finding.target`. Verified if the template matches again; inconclusive if it doesn't match or nuclei can't run. Reuse `apps/nuclei/collector.py` to invoke the binary with `-id <template_id> -u <url>`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_nuclei_verify.py
import pytest
from unittest.mock import patch


def _finding(target="https://example.com", extra=None):
    from apps.core.data.findings.models import Finding
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    return Finding.objects.create(session=s, source="nuclei", check_type="cve",
                                  severity="high", title="CVE-2024-1234", target=target,
                                  extra=extra or {"template_id": "CVE-2024-1234"})


@pytest.mark.django_db
def test_template_matches_again_is_verified():
    from apps.nuclei.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.nuclei.verify._rerun_template",
               return_value=[{"template-id": "CVE-2024-1234", "matched-at": "https://example.com/x"}]):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED
    assert "matched-at" in v.evidence or "example.com" in v.evidence


@pytest.mark.django_db
def test_no_match_is_inconclusive():
    from apps.nuclei.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.nuclei.verify._rerun_template", return_value=[]):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_missing_template_id_is_inconclusive():
    from apps.nuclei.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding(extra={})
    v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_binary_error_is_inconclusive():
    from apps.nuclei.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.nuclei.verify._rerun_template", side_effect=OSError("nuclei missing")):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_nuclei_verify.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
# apps/nuclei/verify.py
"""Re-probe verifier for nuclei findings — re-runs the single matched template."""
import json
import subprocess

from django.conf import settings

from apps.core.engine.verification.verdict import Verdict

_TIMEOUT = 120


def _rerun_template(template_id: str, url: str) -> list:
    """Run nuclei with just this template against this URL; return parsed JSON hits."""
    binary = getattr(settings, "TOOL_NUCLEI", "nuclei")
    proc = subprocess.run(
        [binary, "-id", template_id, "-u", url, "-jsonl", "-silent",
         "-header", f"User-Agent: {getattr(settings, 'OPENEASD_USER_AGENT', 'OpenEASD')}"],
        capture_output=True, text=True, timeout=_TIMEOUT,
    )
    hits = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line:
            try:
                hits.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return hits


def verify_finding(finding) -> Verdict:
    template_id = (finding.extra or {}).get("template_id")
    url = finding.target if finding.target.startswith("http") else f"https://{finding.target}"
    if not template_id:
        return Verdict(Verdict.INCONCLUSIVE, detail="no template_id on finding")
    try:
        hits = _rerun_template(template_id, url)
    except Exception as exc:  # noqa: BLE001
        return Verdict(Verdict.INCONCLUSIVE, detail=f"nuclei re-run failed: {exc}")
    if any(h.get("template-id") == template_id for h in hits):
        matched = next(h for h in hits if h.get("template-id") == template_id)
        return Verdict(Verdict.VERIFIED, evidence=f"matched-at {matched.get('matched-at', url)}")
    return Verdict(Verdict.INCONCLUSIVE, detail="template no longer matches")
```

Add `"verifier"` to `apps/nuclei/apps.py`. Prefer reusing `apps/nuclei/collector.py`'s binary-invocation helper if one exists rather than a fresh `subprocess.run`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_nuclei_verify.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add apps/nuclei/verify.py apps/nuclei/apps.py tests/unit/test_nuclei_verify.py
git commit -m "feat: nuclei re-probe verifier (single-template re-run)"
```

---

### Task 11: Seed verifier — `nmap`

**Files:**
- Create: `apps/nmap/verify.py`
- Modify: `apps/nmap/apps.py` (`tool_meta["verifier"]`)
- Test: `tests/unit/test_nmap_verify.py`

**Interfaces:** Produces `verify_finding(finding) -> Verdict`; registered `"apps.nmap.verify.verify_finding"`.

**Re-probe rule:** re-run the NSE vulners scan against the single `host:port` from `finding.target` and check whether the CVE in `finding.extra["cve"]` still appears. Verified if present; inconclusive if gone or scan fails. Reuse `apps/nmap/collector.py`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_nmap_verify.py
import pytest
from unittest.mock import patch


def _finding(target="example.com:443", extra=None):
    from apps.core.data.findings.models import Finding
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    return Finding.objects.create(session=s, source="nmap", check_type="cve",
                                  severity="high", title="CVE-2023-9999", target=target,
                                  extra=extra or {"cve": "CVE-2023-9999"})


@pytest.mark.django_db
def test_cve_still_reported_is_verified():
    from apps.nmap.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.nmap.verify._rescan_cves", return_value={"CVE-2023-9999", "CVE-2020-1"}):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED


@pytest.mark.django_db
def test_cve_gone_is_inconclusive():
    from apps.nmap.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.nmap.verify._rescan_cves", return_value={"CVE-2020-1"}):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_scan_error_is_inconclusive():
    from apps.nmap.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.nmap.verify._rescan_cves", side_effect=OSError("nmap missing")):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_nmap_verify.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
# apps/nmap/verify.py
"""Re-probe verifier for nmap NSE-vulners CVE findings — re-scans the one host:port."""
from apps.core.engine.verification.verdict import Verdict


def _rescan_cves(host: str, port: int) -> set:
    """Re-run nmap vulners against a single host:port; return the CVE id set.

    Reuse apps/nmap/collector.py's invocation + vulners XML parse rather than
    re-implementing; this wrapper isolates it for test patching.
    """
    from apps.nmap import collector, analyzer
    raw = collector.run_vulners(host, port)          # adjust to real collector fn
    return {c.upper() for c in analyzer.extract_cves(raw)}  # adjust to real parse fn


def _split_target(target: str):
    host, _, port = target.partition(":")
    return host, int(port or 0)


def verify_finding(finding) -> Verdict:
    cve = (finding.extra or {}).get("cve", "").upper()
    host, port = _split_target(finding.target)
    if not cve or not port:
        return Verdict(Verdict.INCONCLUSIVE, detail="missing cve or port on finding")
    try:
        cves = _rescan_cves(host, port)
    except Exception as exc:  # noqa: BLE001
        return Verdict(Verdict.INCONCLUSIVE, detail=f"rescan failed: {exc}")
    if cve in cves:
        return Verdict(Verdict.VERIFIED, evidence=f"{cve} still reported on {host}:{port}")
    return Verdict(Verdict.INCONCLUSIVE, detail=f"{cve} no longer reported")
```

Confirm the real collector/analyzer function names in `apps/nmap/`; extract small reusable helpers if needed. Add `"verifier"` to `apps/nmap/apps.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_nmap_verify.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add apps/nmap/verify.py apps/nmap/apps.py tests/unit/test_nmap_verify.py
git commit -m "feat: nmap re-probe verifier (single host:port CVE re-scan)"
```

---

### Task 12: API — expose verification fields on `/findings/` and `/issues/`

**Files:**
- Modify: `apps/core/data/findings/api.py` (`_serialize_finding`)
- Modify: `apps/core/data/issues/api.py` (`_row`)
- Test: `tests/unit/test_verification_api.py`

**Interfaces:**
- Consumes: `Finding.verification_status`/`verified_at`/`extra["verification"]`, `Issue.verification_status`.
- Produces: `/api/findings/` rows include `verification_status`, `verified_at`, `verification` (the extra sub-dict or null). `/api/issues/` rows include `verification_status`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_verification_api.py
import pytest


@pytest.mark.django_db
def test_findings_api_exposes_verification(auth_client):
    from apps.core.data.domains.models import Domain
    from apps.core.engine.scans.models import ScanSession
    from apps.core.data.findings.models import Finding
    Domain.objects.get_or_create(name="example.com")
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    Finding.objects.create(session=s, source="web_checker", check_type="missing_header",
                           severity="high", title="t", target="example.com",
                           verification_status="verified",
                           extra={"verification": {"verdict": "verified", "evidence": "absent"}})
    row = auth_client.get("/api/findings/?domain=example.com").json()["findings"][0]
    assert row["verification_status"] == "verified"
    assert row["verification"]["evidence"] == "absent"


@pytest.mark.django_db
def test_issues_api_exposes_verification(auth_client):
    from apps.core.data.domains.models import Domain
    from apps.core.data.issues.models import Issue, issue_key
    from django.utils import timezone
    d, _ = Domain.objects.get_or_create(name="example.com")
    now = timezone.now()
    Issue.objects.create(domain=d, source="web_checker", check_type="missing_header",
                         check_id="web_checker:missing_header",
                         key=issue_key("web_checker:missing_header", "example.com"),
                         title="t", target="example.com", severity="high", status="open",
                         first_seen=now, last_seen=now, verification_status="verified")
    row = auth_client.get("/api/issues/?status=").json()["issues"][0]
    assert row["verification_status"] == "verified"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_verification_api.py -v`
Expected: FAIL — `KeyError: 'verification_status'`

- [ ] **Step 3: Write minimal implementation**

In `apps/core/data/findings/api.py` `_serialize_finding`, add:

```python
        "verification_status": f.verification_status,
        "verified_at": f.verified_at.isoformat() if f.verified_at else None,
        "verification": (f.extra or {}).get("verification"),
```

In `apps/core/data/issues/api.py` `_row`, add:

```python
        "verification_status": i.verification_status,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_verification_api.py tests/unit/test_issues_api.py tests/test_api_endpoints.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add apps/core/data/findings/api.py apps/core/data/issues/api.py tests/unit/test_verification_api.py
git commit -m "feat: expose verification fields on findings + issues API"
```

---

### Task 13: API — on-demand verify endpoints

**Files:**
- Modify: `apps/core/engine/scans/api.py` (add `POST /api/scans/<uuid>/verify/`)
- Modify: `apps/core/data/findings/api.py` (add `POST /api/findings/<id>/verify/`)
- Test: `tests/unit/test_verification_api.py` (extend)

**Interfaces:**
- Consumes: `verify_session` (Task 5); per-finding, a single-finding verify path.
- Produces: `POST /api/scans/<uuid>/verify/` → 409 if the scan is running, else runs `verify_session` and returns `{verified, inconclusive, unverified}` counts. `POST /api/findings/<id>/verify/` → re-verifies one finding, returns its serialized row.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/unit/test_verification_api.py
import pytest
from unittest.mock import patch


@pytest.mark.django_db
def test_scan_verify_endpoint_409_when_running(auth_client):
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="running")
    r = auth_client.post(f"/api/scans/{s.session_id}/verify/", data={}, content_type="application/json")
    assert r.status_code == 409


@pytest.mark.django_db
def test_scan_verify_endpoint_runs_and_returns_counts(auth_client):
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    with patch("apps.core.engine.scans.api.verify_session") as mock_v:
        r = auth_client.post(f"/api/scans/{s.session_id}/verify/", data={}, content_type="application/json")
    assert r.status_code == 200
    mock_v.assert_called_once()


@pytest.mark.django_db
def test_finding_verify_endpoint(auth_client):
    from apps.core.engine.scans.models import ScanSession
    from apps.core.data.findings.models import Finding
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    f = Finding.objects.create(session=s, source="web_checker", check_type="missing_header",
                               severity="high", title="t", target="example.com")
    from apps.core.engine.verification.verdict import Verdict
    with patch("apps.core.data.findings.api.verify_one_finding",
               return_value=Verdict(Verdict.VERIFIED, evidence="absent")):
        r = auth_client.post(f"/api/findings/{f.id}/verify/", data={}, content_type="application/json")
    assert r.status_code == 200
    assert r.json()["verification_status"] == "verified"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_verification_api.py -v -k verify_endpoint`
Expected: FAIL — 404 (routes not defined)

- [ ] **Step 3: Write minimal implementation**

First add a single-finding helper to `apps/core/engine/verification/verifier.py`:

```python
def verify_one_finding(finding):
    """Verify a single finding on demand (used by the per-finding API)."""
    from apps.core.engine.workflows.registry import get_tool_active, get_tool_verifiers
    verifier = get_tool_verifiers().get(finding.source)
    if verifier is None:
        v = Verdict(Verdict.INCONCLUSIVE, detail="no verifier for this tool")
    elif get_tool_active().get(finding.source, True) and not _authorized_for(finding.session):
        v = Verdict(Verdict.INCONCLUSIVE, detail="verification skipped: no authorization")
    else:
        try:
            v = verifier(finding)
        except Exception:  # noqa: BLE001
            v = Verdict(Verdict.INCONCLUSIVE, detail="verifier error")
    _apply(finding, v)
    return v
```

In `apps/core/engine/scans/api.py` (module-level import `from apps.core.engine.verification.verifier import verify_session`):

```python
@router.post("/{session_uuid}/verify/")
def verify_scan(request, session_uuid: str):
    session = get_object_or_404(ScanSession, session_id=session_uuid)
    if session.status == "running":
        raise HttpError(409, "scan is still running")
    verify_session(session)
    from django.db.models import Count
    counts = dict(session.findings.values_list("verification_status")
                  .annotate(n=Count("id")).values_list("verification_status", "n"))
    return {"verified": counts.get("verified", 0),
            "inconclusive": counts.get("inconclusive", 0),
            "unverified": counts.get("unverified", 0)}
```

In `apps/core/data/findings/api.py` (import `from apps.core.engine.verification.verifier import verify_one_finding`):

```python
@router.post("/{finding_id}/verify/")
def verify_finding_endpoint(request, finding_id: int):
    finding = get_object_or_404(Finding, id=finding_id)
    verify_one_finding(finding)
    finding.refresh_from_db()
    return _serialize_finding(finding)
```

Confirm the ScanSession UUID lookup field name (`session_id` vs `uuid`) matches the other `/api/scans/<uuid>/` routes in this file.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_verification_api.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add apps/core/engine/scans/api.py apps/core/data/findings/api.py apps/core/engine/verification/verifier.py tests/unit/test_verification_api.py
git commit -m "feat: on-demand verify endpoints (scan + single finding)"
```

---

### Task 14: Report — verification badge + evidence line

**Files:**
- Modify: `apps/core/console/reports/views.py` (finding rendering + the Issue Register section)
- Modify: the report template/HTML builder used by `_render_pdf` (find where per-finding rows are built in `reports/views.py`)
- Test: `tests/unit/test_reports.py` (add cases)

**Interfaces:**
- Consumes: `Finding.verification_status`, `extra["verification"]["evidence"]`.
- Produces: each finding in the PDF shows a `Verified` / `Inconclusive` / `Unverified` badge and, when present, an `Evidence:` line. Absent verification (all `unverified`, no evidence) ⇒ report HTML unchanged from before this task for that finding.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/unit/test_reports.py
    def test_report_shows_verified_badge_and_evidence(self):
        # Build a scan with one verified finding; assert the captured HTML.
        html = self._render_report_html_with_finding(
            verification_status="verified",
            extra={"verification": {"verdict": "verified", "evidence": "CSP still absent"}},
        )
        assert "Verified" in html
        assert "CSP still absent" in html

    def test_report_unverified_finding_shows_no_evidence_line(self):
        html = self._render_report_html_with_finding(verification_status="unverified", extra={})
        assert "Evidence:" not in html
```

(Implement `_render_report_html_with_finding` as a small helper in the test class mirroring the existing `test_reports.py` PDF-HTML capture pattern — the file already mocks `_render_pdf` and asserts on captured HTML; reuse that fixture.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_reports.py -v -k verif`
Expected: FAIL — badge/evidence not in HTML

- [ ] **Step 3: Write minimal implementation**

In the per-finding rendering in `apps/core/console/reports/views.py`, add a badge derived from `finding.verification_status` (map `verified→"Verified"`, `inconclusive→"Inconclusive"`, `unverified→"Unverified"`) and, when `finding.extra.get("verification", {}).get("evidence")`, an `Evidence: <text>` line. Keep the change additive so an all-unverified/no-evidence finding renders exactly as before (guard the Evidence line on presence).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_reports.py -v`
Expected: PASS (all existing + 2 new)

- [ ] **Step 5: Commit**

```bash
git add apps/core/console/reports/views.py tests/unit/test_reports.py
git commit -m "feat: report shows verification badge + evidence line"
```

---

### Task 15: AI adjudication layer (optional, AI-gated)

**Files:**
- Create: `apps/core/console/ai/adjudicate.py`
- Modify: `apps/core/console/ai/hooks.py` (call it from `run_ai_post_scan`)
- Test: `tests/unit/test_ai_adjudication.py`

**Interfaces:**
- Consumes: `guard.is_ai_active()`, the AI `client` (same one triage uses), `Finding.verification_status`/`extra`.
- Produces: `run_adjudication(session) -> None`. When AI active, for each `verified`/`inconclusive` medium+ finding it writes `extra["verification"]["ai"] = {"confidence": float, "rationale": str}`. Never changes `verification_status` or `Finding.status`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_ai_adjudication.py
import pytest
from unittest.mock import patch


def _finding(s, status="verified"):
    from apps.core.data.findings.models import Finding
    return Finding.objects.create(session=s, source="web_checker", check_type="missing_header",
                                  severity="high", title="t", target="example.com",
                                  verification_status=status,
                                  extra={"verification": {"verdict": status, "evidence": "x"}})


@pytest.mark.django_db
def test_noop_when_ai_inactive():
    from apps.core.console.ai.adjudicate import run_adjudication
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    f = _finding(s)
    with patch("apps.core.console.ai.adjudicate.guard.is_ai_active", return_value=False):
        run_adjudication(s)
    f.refresh_from_db()
    assert "ai" not in f.extra["verification"]


@pytest.mark.django_db
def test_annotates_but_never_flips_verdict_when_active():
    from apps.core.console.ai.adjudicate import run_adjudication
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    f = _finding(s, status="verified")
    with patch("apps.core.console.ai.adjudicate.guard.is_ai_active", return_value=True), \
         patch("apps.core.console.ai.adjudicate._adjudicate_one",
               return_value={"confidence": 0.9, "rationale": "clear"}):
        run_adjudication(s)
    f.refresh_from_db()
    assert f.verification_status == "verified"           # unchanged
    assert f.extra["verification"]["ai"]["confidence"] == 0.9


@pytest.mark.django_db
def test_ai_failure_is_swallowed():
    from apps.core.console.ai.adjudicate import run_adjudication
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    _finding(s)
    with patch("apps.core.console.ai.adjudicate.guard.is_ai_active", return_value=True), \
         patch("apps.core.console.ai.adjudicate._adjudicate_one", side_effect=RuntimeError("cf down")):
        run_adjudication(s)  # must not raise
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/test_ai_adjudication.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write minimal implementation**

```python
# apps/core/console/ai/adjudicate.py
"""Optional AI adjudication of verification verdicts. AI advises, never decides:
it annotates extra['verification']['ai'] and NEVER changes verification_status
or Finding.status. No-op unless guard.is_ai_active(). Fail-graceful.
"""
import logging

from apps.core.constants import SEVERITY_RANK

from . import guard

logger = logging.getLogger(__name__)


def _adjudicate_one(finding):
    """One bounded Cloudflare call; returns {'confidence': float, 'rationale': str}.
    Reuse apps/core/console/ai/client.py the way run_triage does (same per-scan
    budget + AIInvocation audit row). Returns None if the model gives nothing usable.
    """
    from .client import call_model  # adjust to the real client entrypoint
    ...  # build a small prompt from finding.title + extra['verification']; parse the reply
    return None


def run_adjudication(session) -> None:
    if not guard.is_ai_active():
        return
    try:
        findings = [f for f in session.findings.all()
                    if f.verification_status in ("verified", "inconclusive")
                    and SEVERITY_RANK.get(f.severity, -1) >= SEVERITY_RANK.get("medium", 99)]
        for f in findings:
            try:
                ai = _adjudicate_one(f)
            except Exception:  # noqa: BLE001
                logger.exception("[adjudicate:%s] finding %s failed", session.id, f.id)
                continue
            if not ai:
                continue
            extra = dict(f.extra or {})
            v = dict(extra.get("verification") or {})
            v["ai"] = {"confidence": ai["confidence"], "rationale": ai["rationale"]}
            extra["verification"] = v
            f.extra = extra
            f.save(update_fields=["extra"])  # never touches verification_status/status
    except Exception:  # noqa: BLE001
        logger.exception("[adjudicate:%s] adjudication failed — scan unaffected", session.id)
```

In `apps/core/console/ai/hooks.py`, inside `run_ai_post_scan` (after triage/summaries), add a fail-graceful call:

```python
    from .adjudicate import run_adjudication
    run_adjudication(session)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/test_ai_adjudication.py tests/unit/test_ai_pipeline.py tests/unit/test_ai_invariants.py -v`
Expected: PASS (adjudication works; AI invariants still hold)

- [ ] **Step 5: Commit**

```bash
git add apps/core/console/ai/adjudicate.py apps/core/console/ai/hooks.py tests/unit/test_ai_adjudication.py
git commit -m "feat: optional AI adjudication of verification verdicts (advisory only)"
```

---

### Task 16: Invariant guard + docs + spec status flip

**Files:**
- Modify: `tests/unit/test_ai_pipeline.py` (hold verification constant in the AI-off byte-identical test)
- Modify: `tests/unit/test_verification_pipeline.py` (add the disabled byte-identical guard)
- Modify: `docs/03-system.md` (new `apps/core/engine/verification/` package + the finalize step)
- Modify: `CLAUDE.md` (finalize flow + new engine package + verification fields; bump the test total)
- Modify: `docs/specs/2026-09-15-finding-verification.md` (flip Status to ✅ Implemented)
- Test: covered by the two test files above

**Interfaces:** none new — documentation + invariant lock.

- [ ] **Step 1: Write the failing test**

```python
# add to tests/unit/test_verification_pipeline.py
@pytest.mark.django_db
def test_disabled_leaves_findings_unverified(settings):
    settings.FINDING_VERIFICATION_ENABLED = False
    from apps.core.engine.scans import pipeline
    from apps.core.engine.scans.models import ScanSession
    from apps.core.data.findings.models import Finding
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="running")
    f = Finding.objects.create(session=s, source="web_checker", check_type="missing_header",
                               severity="high", title="t", target="example.com")
    pipeline._finalize_session(s)
    f.refresh_from_db()
    assert f.verification_status == "unverified"  # untouched when disabled
```

- [ ] **Step 2: Run test to verify it fails (or passes if already correct)**

Run: `uv run pytest tests/unit/test_verification_pipeline.py::test_disabled_leaves_findings_unverified -v`
Expected: PASS (Task 6 already gates it) — this is the regression lock.

- [ ] **Step 3: Update the AI-off invariant test + docs**

- In `tests/unit/test_ai_pipeline.py`, find the "AI-off finalize byte-identical" test; set `settings.FINDING_VERIFICATION_ENABLED = False` in its setup so verification (a separate feature) doesn't perturb the AI-specific comparison. Confirm the test still asserts zero AI traces.
- `docs/03-system.md`: add `verification` to the engine layer app list and add the verification step to the finalize/fact-flow description (between asset and issue rollup).
- `CLAUDE.md`: add the verification step to the "Scan flow" finalize block; add `apps/core/engine/verification/` to the engine layer; note `Finding.verification_status`/`verified_at` + `Issue.verification_status`; add the new test files to the test table and bump **Total** by a real `--collect-only` count.
- `docs/specs/2026-09-15-finding-verification.md`: change the Status header from `📝 Proposed` to `✅ Implemented` with the PR reference.

- [ ] **Step 4: Run the full fast suite + coverage**

Run: `uv run pytest tests/ --ignore=tests/unit/test_domain_security.py`
Expected: PASS, coverage ≥ 80%.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/test_ai_pipeline.py tests/unit/test_verification_pipeline.py docs/03-system.md CLAUDE.md docs/specs/2026-09-15-finding-verification.md
git commit -m "test: lock verification invariants; docs: finalize step + engine package"
```

---

## Self-Review

**Spec coverage:**
- §2 mechanism (deterministic + AI layer) → Tasks 5 (deterministic) + 15 (AI). ✅
- §3 verdict states → Task 1 + used throughout. ✅
- §4 data model (Finding + Issue fields, extra schema) → Tasks 3, 4, 5. ✅
- §5 verifier contract + registry → Tasks 2, 7 (contract established), 8–11 (seeds). ✅
- §6 orchestrator (severity gate, auth gate, idempotent, fail-graceful, low-mem sequential) → Task 5. ✅ (Sequential is the default loop; no concurrency added.)
- §7 pipeline seam (after asset, before issue rollup; disabled = byte-identical; subscans skip) → Task 6 + 16. Subscan skip: `_finalize_session` already early-returns for subscans before the rollups, so verification inherits the skip — noted, no extra task needed. ✅
- §8 AI adjudication (gated, advisory, budget, audit, no-op off) → Task 15. ✅
- §9 surfaces (API fields, verify endpoints, report badge+evidence) → Tasks 12, 13, 14. ✅
- §10 settings → Task 1. ✅
- §11 rollout DoD → Tasks map 1:1. ✅
- §12 invariants → Tasks 5, 6, 15, 16. ✅

**Placeholder scan:** The `...` in Tasks 9, 11, 15 are explicit "reuse the tool's existing collector/analyzer / client — confirm the real function name" instructions, not hidden work; each names the file and the function role. Acceptable because the exact helper name must be read from the tool at execution time; the surrounding contract (inputs, outputs, Verdict mapping) is fully specified.

**Type consistency:** `Verdict(verdict, evidence, detail)` and `verify_finding(finding) -> Verdict` are used identically in Tasks 5, 7–11, 13. `verification_status` string values (`unverified`/`verified`/`inconclusive`) are consistent across model, orchestrator, API, report, rollup. `get_tool_verifiers()` / `get_tool_active()` names match between Tasks 2 and 5.

**Known integration points to confirm at execution (not gaps — repo-specific names):** the `DomainAuthorization` query fields (Task 5 `_authorized_for`), the tool-app enumeration helper in `registry.py` (Task 2), the ScanSession UUID field name (Task 13), and each tool's collector/analyzer helper names (Tasks 8–11). Each is flagged inline with the file to read.
