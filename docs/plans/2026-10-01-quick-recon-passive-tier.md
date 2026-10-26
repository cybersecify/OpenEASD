# Quick Recon — Passive-Tier Formalization — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Formalize a light/deep split within the passive tool set (a
`tool_meta["quick_recon"]` flag + registry accessor + `light_passive_tools()`
helper) and back the light tier with a predefined, non-default "Quick Recon"
workflow containing exactly the four apex-only passive tools.

**Architecture:** Mirror the existing `active` flag end-to-end — a safe-defaulted
`tool_meta` boolean stored in the registry, exposed by a `get_tool_*` accessor,
and a derived single-source-of-truth helper. The workflow is a data migration
shaped like `0022_create_passive_scan_workflow.py`. A drift-lock test binds the
flag to the workflow membership in both directions. Purely additive.

**Tech Stack:** Django 5.2, Django-Ninja, pytest (`uv run pytest`), data
migrations.

**Spec:** `docs/specs/2026-10-01-quick-recon-passive-tier.md`

## Global Constraints

- **Commands:** always `uv run pytest` / `uv run manage.py` / `uv run python` — never bare `python`.
- **Fast test suite:** `uv run pytest tests/ --ignore=tests/unit/test_domain_security.py`.
- **The light set is exactly four tools:** `domain_security`, `dns_history`, `hudson_rock`, `breach_check`.
- **The `quick_recon` flag defaults `False` in the registry** — an unclassified tool is never light (mirrors `active` defaulting `True`).
- **`light_passive_tools()` = passive AND `quick_recon`** — a stray `quick_recon=True` on an active tool must be a no-op, never counted as light.
- **Additive only:** no change to Full Scan, Passive Scan, the authorization boundary, or any tool's runtime behavior.
- **Branch:** `feat/quick-recon-passive-tier` (already created). Commit prefixes per CLAUDE.md (`feat:` / `test:` / `docs:`). Every commit message ends with the two attribution trailers (`Co-Authored-By: Claude Opus 4.8 …` + `Claude-Session: …`).
- **No frontend changes** (backend-first / frontend-last rule) — the React badge is a documented follow-up.

---

### Task 1: Registry classification — `quick_recon` flag, accessor, and `light_passive_tools()` helper

**Files:**
- Modify: `apps/core/engine/workflows/registry.py` (registry dict build ~line 42-61; add accessor after `get_tool_active` ~line 122; add helper after `is_passive_tool_set` ~line 136)
- Modify: `apps/domain_security/apps.py`, `apps/dns_history/apps.py`, `apps/hudson_rock/apps.py`, `apps/breach_check/apps.py` (add `"quick_recon": True` to each `tool_meta`)
- Test: `tests/unit/test_quick_recon.py` (new)

**Interfaces:**
- Consumes: `get_registry()`, `get_tool_active()` (existing in `registry.py`).
- Produces:
  - `get_tool_quick_recon() -> dict[str, bool]` — tool name → flag (default `False`).
  - `light_passive_tools() -> set[str]` — `{name for name, info in get_registry().items() if info.get("quick_recon") and not info["active"]}`.
  - `tool_meta["quick_recon"] = True` on exactly the four light tools.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_quick_recon.py`:

```python
"""Quick Recon — the light passive tier.

Covers the registry `quick_recon` flag + its safe default, the
`light_passive_tools()` helper (passive AND quick_recon), and — in Task 2 —
the predefined 'Quick Recon' workflow and its drift lock against the helper.
"""

import pytest

LIGHT = {"domain_security", "dns_history", "hudson_rock", "breach_check"}


class TestQuickReconFlag:
    def test_four_light_tools_flagged(self):
        from apps.core.engine.workflows.registry import get_tool_quick_recon
        qr = get_tool_quick_recon()
        for tool in LIGHT:
            assert qr.get(tool) is True, f"{tool} should be quick_recon"

    def test_flag_defaults_false_for_unflagged_tool(self):
        # A heavy passive tool and an active tool are NOT quick_recon.
        from apps.core.engine.workflows.registry import get_tool_quick_recon
        qr = get_tool_quick_recon()
        assert qr.get("tldsquatting") is False      # passive but heavy
        assert qr.get("nmap") is False              # active
        assert qr.get("subfinder") is False         # passive but heavy

    def test_every_tool_has_a_quick_recon_flag(self):
        from apps.core.engine.workflows.registry import (
            get_tool_quick_recon,
            get_registry,
        )
        qr = get_tool_quick_recon()
        for name in get_registry():
            assert name in qr
            assert isinstance(qr[name], bool)


class TestLightPassiveHelper:
    def test_light_passive_tools_is_exactly_the_four(self):
        from apps.core.engine.workflows.registry import light_passive_tools
        assert light_passive_tools() == LIGHT

    def test_light_tools_are_all_passive(self):
        from apps.core.engine.workflows.registry import (
            light_passive_tools,
            get_tool_active,
        )
        active = get_tool_active()
        for tool in light_passive_tools():
            assert active[tool] is False

    def test_active_tool_with_stray_flag_is_not_light(self, monkeypatch):
        # Defensive: quick_recon=True on an active tool must be a no-op.
        import apps.core.engine.workflows.registry as reg
        fake = {
            "mystery": {"active": True, "quick_recon": True},
            "domain_security": {"active": False, "quick_recon": True},
        }
        monkeypatch.setattr(reg, "get_registry", lambda: fake)
        assert reg.light_passive_tools() == {"domain_security"}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/test_quick_recon.py -v`
Expected: FAIL — `get_tool_quick_recon` / `light_passive_tools` don't exist (ImportError).

- [ ] **Step 3: Add the `quick_recon` flag to the registry dict**

In `apps/core/engine/workflows/registry.py`, inside the `_registry[tool_name] = {...}` literal (right after the `"active": meta.get("active", True),` line ~line 60), add:

```python
            # quick_recon=True marks a LIGHT passive tool — apex-scoped, fast,
            # no discovery fan-out — eligible for the Quick Recon workflow.
            # Default False (safe): an unclassified tool is never light, so a
            # new tool can't silently join the fast mode. Only meaningful on
            # passive tools; light_passive_tools() gates on active=False.
            "quick_recon": meta.get("quick_recon", False),
```

- [ ] **Step 4: Add the accessor and the helper**

In `registry.py`, after `get_tool_active()` (~line 122) add:

```python
def get_tool_quick_recon() -> dict[str, bool]:
    """Dynamic map: tool_name → True if the tool is a LIGHT passive tool.

    Light = apex-scoped, fast, no discovery fan-out (Quick Recon eligible).
    Default False; only meaningful on passive tools (see light_passive_tools).
    """
    return {name: info["quick_recon"] for name, info in get_registry().items()}
```

After `is_passive_tool_set()` (~line 136) add:

```python
def light_passive_tools() -> set[str]:
    """The light passive tier: tools that are PASSIVE and quick_recon.

    Single source of truth for the taxonomy. "Deep passive" is the derived
    complement (passive and not in this set); active tools have no tier — a
    stray quick_recon=True on an active tool is excluded here (no-op), never
    an authorization hole.
    """
    reg = get_registry()
    return {
        name
        for name, info in reg.items()
        if info.get("quick_recon") and not info["active"]
    }
```

- [ ] **Step 5: Flag the four light tools**

In each of `apps/domain_security/apps.py`, `apps/dns_history/apps.py`, `apps/hudson_rock/apps.py`, `apps/breach_check/apps.py`, add one line inside the existing `tool_meta` dict (next to `"active": False,`):

```python
        "quick_recon": True,  # light passive — apex-scoped, fast (Quick Recon)
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/test_quick_recon.py -v`
Expected: PASS (all tests in `TestQuickReconFlag` + `TestLightPassiveHelper`).

- [ ] **Step 7: Run the broader workflow/registry suites for regressions**

Run: `uv run pytest tests/unit/test_passive_scan.py tests/unit/test_render_pipeline_diagram.py tests/unit/test_default_workflow.py -q`
Expected: PASS (the additive flag must not disturb existing classification tests).

- [ ] **Step 8: Commit**

```bash
git add apps/core/engine/workflows/registry.py apps/domain_security/apps.py apps/dns_history/apps.py apps/hudson_rock/apps.py apps/breach_check/apps.py tests/unit/test_quick_recon.py
git commit -m "feat: add quick_recon tier flag + light_passive_tools() helper

<attribution trailers>"
```

---

### Task 2: The Quick Recon workflow (data migration) + drift-lock test

**Files:**
- Create: `apps/core/engine/workflows/migrations/0036_create_quick_recon_workflow.py`
- Test: `tests/unit/test_quick_recon.py` (append a `TestQuickReconWorkflow` class)

**Interfaces:**
- Consumes: `light_passive_tools()`, `is_passive_tool_set()` (Task 1); the `Workflow`/`WorkflowStep` models; `wf.enabled_tools()` (existing method returning tool-name list).
- Produces: a predefined non-default `Workflow` named `"Quick Recon"` with the four light tools as enabled steps.

- [ ] **Step 1: Write the failing drift-lock tests**

Append to `tests/unit/test_quick_recon.py`:

```python
@pytest.mark.django_db
class TestQuickReconWorkflow:
    def test_workflow_exists_and_is_not_default(self):
        from apps.core.engine.workflows.models import Workflow
        wf = Workflow.objects.get(name="Quick Recon")
        assert wf.is_default is False

    def test_workflow_membership_equals_light_passive_set(self):
        # Drift lock: the workflow's tools == light_passive_tools(), both ways.
        from apps.core.engine.workflows.models import Workflow
        from apps.core.engine.workflows.registry import light_passive_tools
        wf = Workflow.objects.get(name="Quick Recon")
        assert set(wf.enabled_tools()) == light_passive_tools()

    def test_workflow_is_entirely_passive(self):
        # No-auth property: every tool in Quick Recon must be passive.
        from apps.core.engine.workflows.models import Workflow
        from apps.core.engine.workflows.registry import is_passive_tool_set
        wf = Workflow.objects.get(name="Quick Recon")
        assert is_passive_tool_set(wf.enabled_tools()) is True
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/test_quick_recon.py::TestQuickReconWorkflow -v`
Expected: FAIL — `Workflow.DoesNotExist: Workflow matching query does not exist` (no migration yet).

- [ ] **Step 3: Write the migration**

Create `apps/core/engine/workflows/migrations/0036_create_quick_recon_workflow.py`:

```python
"""Create the 'Quick Recon' workflow — the LIGHT passive tier.

Quick Recon is the instant, no-auth first look: four apex-scoped passive tools
that each hit the apex (or a third-party API keyed on it) with a handful of
lookups and finish in seconds — no subdomain/CT/archive enumeration, no
discovery fan-out, nothing downstream depending on them:

    domain_security  — DNS/DNSSEC/CAA/email-auth + RDAP via public resolvers
    dns_history      — one passive-DNS API call
    hudson_rock      — one keyless infostealer-exposure API call
    breach_check     — one keyless/BYOK data-breach API call

All four are passive (active=False), so Quick Recon needs NO DomainAuthorization
for a `now` scan (see apps/core/engine/scans/api.py). The membership here MUST
stay in sync with registry.light_passive_tools() (passive AND quick_recon);
tests/unit/test_quick_recon.py::TestQuickReconWorkflow binds the two in both
directions, so a flag/workflow drift fails CI.

Not the default workflow — Full Scan (active, gated) remains the default.
"""

from django.db import migrations

# Light passive tools in pipeline-phase order. Order is cosmetic (the runner
# regroups by registry phase); it mirrors the pipeline for a readable UI.
_TOOLS = [
    ("domain_security", 1),
    ("dns_history", 2),
    ("hudson_rock", 3),
    ("breach_check", 4),
]


def create_quick_recon_workflow(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    WorkflowStep = apps.get_model("workflow", "WorkflowStep")

    if Workflow.objects.filter(name="Quick Recon").exists():
        return  # idempotent

    wf = Workflow.objects.create(
        name="Quick Recon",
        description="Instant passive snapshot — four apex-scoped, keyless-capable "
                    "tools (domain posture, historical DNS, infostealer and "
                    "data-breach exposure). Public/third-party data only, no "
                    "packets to the target, finishes in seconds. Requires no "
                    "domain authorization.",
        is_default=False,
    )
    for tool, order in _TOOLS:
        WorkflowStep.objects.create(workflow=wf, tool=tool, order=order, enabled=True)


def remove_quick_recon_workflow(apps, schema_editor):
    Workflow = apps.get_model("workflow", "Workflow")
    Workflow.objects.filter(name="Quick Recon").delete()


class Migration(migrations.Migration):
    dependencies = [
        ("workflow", "0035_supersede_typosquat_with_tldsquatting"),
    ]

    operations = [
        migrations.RunPython(create_quick_recon_workflow, remove_quick_recon_workflow),
    ]
```

- [ ] **Step 4: Verify the migration graph is clean**

Run: `uv run manage.py makemigrations --check --dry-run`
Expected: "No changes detected" (the data migration introduces no model changes). If it reports a missing migration, STOP — a model drifted; investigate before continuing.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/test_quick_recon.py -v`
Expected: PASS (migration runs in the test DB → the workflow exists; membership == light set; all passive).

- [ ] **Step 6: Commit**

```bash
git add apps/core/engine/workflows/migrations/0036_create_quick_recon_workflow.py tests/unit/test_quick_recon.py
git commit -m "feat: add predefined Quick Recon workflow (light passive tier)

<attribution trailers>"
```

---

### Task 3: Expose the tier in the tools API

**Files:**
- Modify: `apps/core/engine/workflows/api.py` (`list_tools`, ~line 71-90 — add `get_tool_quick_recon` import at top of file alongside the other registry imports, and one key to the per-tool dict)
- Test: `tests/test_api_endpoints.py` OR `tests/unit/test_quick_recon.py` (append an API assertion — prefer `test_quick_recon.py` to keep the feature self-contained)

**Interfaces:**
- Consumes: `get_tool_quick_recon()` (Task 1); the existing `GET /api/workflows/tools/` endpoint + its JWT auth test client.
- Produces: each tool dict in the `tools` list gains a `"quick_recon": bool` key. No existing key changes.

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_quick_recon.py`. Mirror the auth/client setup used elsewhere in the suite (JWT bearer via `/api/token/pair`); if a shared fixture exists for an authed client, use it. Minimal shape:

```python
@pytest.mark.django_db
class TestQuickReconToolsApi:
    def test_tools_endpoint_exposes_quick_recon_flag(self, client, django_user_model):
        import json
        django_user_model.objects.create_user(username="qr", password="pw-123456")
        tok = client.post(
            "/api/token/pair",
            data=json.dumps({"username": "qr", "password": "pw-123456"}),
            content_type="application/json",
        ).json()["access"]
        resp = client.get(
            "/api/workflows/tools/", HTTP_AUTHORIZATION=f"Bearer {tok}"
        )
        assert resp.status_code == 200
        by_key = {t["key"]: t for t in resp.json()["tools"]}
        assert by_key["domain_security"]["quick_recon"] is True
        assert by_key["tldsquatting"]["quick_recon"] is False
        # additive: the existing active flag is untouched
        assert by_key["domain_security"]["active"] is False
```

NOTE for the implementer: if the suite already has an authed-client fixture (grep `tests/test_api_endpoints.py` for how it builds the Bearer token), reuse that pattern instead of hand-rolling the token here — keep it consistent with the codebase.

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_quick_recon.py::TestQuickReconToolsApi -v`
Expected: FAIL — `KeyError: 'quick_recon'` (the endpoint doesn't emit the key yet).

- [ ] **Step 3: Add the import**

In `apps/core/engine/workflows/api.py`, add `get_tool_quick_recon` to the existing registry import block (where `get_tool_active` is imported, ~line 14).

- [ ] **Step 4: Emit the key**

In `list_tools` (~line 71), add `quick_recon = get_tool_quick_recon()` next to `active = get_tool_active()`, and add one key to the per-tool dict (right after the `"active": active.get(key, True),` line):

```python
            # quick_recon = light passive tier (apex-scoped, fast). Lets the UI
            # badge light vs deep passive and offer the Quick Recon mode.
            "quick_recon": quick_recon.get(key, False),
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/unit/test_quick_recon.py::TestQuickReconToolsApi -v`
Expected: PASS.

- [ ] **Step 6: Run the API smoke suite for regressions**

Run: `uv run pytest tests/test_api_endpoints.py -q`
Expected: PASS (additive key, no existing contract broken).

- [ ] **Step 7: Commit**

```bash
git add apps/core/engine/workflows/api.py tests/unit/test_quick_recon.py
git commit -m "feat: expose quick_recon tier in the tools API

<attribution trailers>"
```

---

### Task 4: Documentation

**Files:**
- Modify: `CLAUDE.md` (Scan pipeline → passive/active section: document the Quick Recon workflow next to Passive Scan + the light/deep passive definition; "Definition of done for adding a tool" list: add a line about setting `quick_recon`)
- Modify: `docs/03-system.md` (note the light/deep passive split at system altitude)

**Interfaces:**
- Consumes: nothing (prose). Describes Tasks 1-3 as shipped.
- Produces: no code; doc parity with the feature (CLAUDE.md doc-drift rule).

- [ ] **Step 1: Update CLAUDE.md**

In the **"Passive vs active scan modes"** area (near the "Passive Scan" workflow paragraph), add a paragraph describing the **Quick Recon** workflow: the four light tools (`domain_security`, `dns_history`, `hudson_rock`, `breach_check`), that it is predefined + non-default, inherits the no-auth bypass (all passive), and finishes in seconds. State the taxonomy: *light passive* = passive AND `quick_recon` (`registry.light_passive_tools()`); *deep passive* = passive and not light; the drift lock is `test_quick_recon.py`.

In the **"Definition of done for adding (or removing) a tool"** numbered list (step 3 is the `"active"` flag), add a sub-point: when a new tool is passive AND apex-scoped + fast (no discovery fan-out), set `"quick_recon": True` so it joins Quick Recon — and the `test_quick_recon.py` drift lock then requires it in the workflow (keep the migration + flag in sync).

- [ ] **Step 2: Update docs/03-system.md**

Add a short note (in whatever section covers the tool classification / passive-active model) that the passive set is further split into **light** (`quick_recon`, Quick Recon workflow) and **deep** (the derived complement), and that this is a cost/scope axis distinct from the `_LOW_MEM_PARALLEL_SAFE` memory/IO axis.

- [ ] **Step 3: Sanity-check the docs reference real symbols**

Verify by grep that the names cited in the docs exist in code:

Run: `grep -rn "light_passive_tools\|quick_recon\|Quick Recon" apps/ tests/ | head`
Expected: the helper, the flag, and the workflow name all resolve to real definitions added in Tasks 1-2.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md docs/03-system.md
git commit -m "docs: document Quick Recon workflow + light/deep passive tier

<attribution trailers>"
```

---

## Self-Review

**1. Spec coverage:**
- §2 light set (four tools) → Task 1 Step 5 (flags) + Task 2 migration `_TOOLS` + Task 1/2 tests lock membership. ✅
- §3 flag + registry default + accessor + helper → Task 1 Steps 3-4, tests in Step 1. ✅
- §4 Quick Recon workflow migration (non-default, idempotent, reverse) → Task 2 Step 3. ✅
- §5 drift lock (membership both ways + all-passive) + registry/default tests → Task 1 + Task 2 tests. ✅
- §6 tools-API exposure (additive, backend only) → Task 3. ✅
- §7 docs (CLAUDE.md + 03-system, no PRD/DDD) → Task 4. ✅
- §8 invariants → covered by the Task 1/2 tests (default False, passive-AND gate, membership equality, all-passive). ✅
- §9 non-goals (no `_LOW_MEM_PARALLEL_SAFE`, no frontend, not default/scheduled, no deep workflow) → respected; nothing in any task touches them. ✅

**2. Placeholder scan:** The only intentional stand-in is `<attribution trailers>` in commit messages (the controller fills the two real trailer lines at commit time per Global Constraints) and the Task 3 NOTE to reuse an existing authed-client fixture if present. No TBD/TODO, no "add error handling", all code blocks concrete.

**3. Type consistency:** `get_tool_quick_recon() -> dict[str, bool]` and `light_passive_tools() -> set[str]` are referenced identically in Tasks 1-3 and the tests. `wf.enabled_tools()` returns a tool-name iterable (confirmed from `test_passive_scan.py`). Migration dependency `0035_supersede_typosquat_with_tldsquatting` is the current latest. Workflow name string `"Quick Recon"` is identical in the migration and every test.
