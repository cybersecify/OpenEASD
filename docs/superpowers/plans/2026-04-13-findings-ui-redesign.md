# Findings Page UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 4 clickable severity summary cards (open findings only) above the findings table and slim the table from 7 to 5 columns by removing the domain column and replacing the "View Scan" text link with a small ↗ icon.

**Architecture:** Two changes working together — the view adds 4 count context variables, and the templates add the cards + drop the domain column. Cards are plain `<a>` links to `?severity=X`; selected state is rendered server-side using the existing `severity` context variable.

**Tech Stack:** Django 5+, Tailwind CSS (CDN), HTMX (for partial refresh), existing `latest_session_ids()` query helper.

---

## File Map

| File | Change |
|---|---|
| `apps/core/scans/views.py` | Add 4 `count_open_*` vars to full-page render (lines 365–431) |
| `templates/findings/list.html` | Add severity cards grid; remove Domain `<th>` |
| `templates/partials/vuln_rows.html` | Remove domain `<td>`; icon-ify scan link; fix colspan |
| `tests/unit/test_scans.py` | Add `TestFindingsPageCards` class (6 tests) |

---

## Task 1: Add count context variables to vulnerability_list view

**Spec ref:** View Changes section — 4 new `count_open_*` context variables, full-page render only.

**Files:**
- Modify: `apps/core/scans/views.py:365–431`
- Test: `tests/unit/test_scans.py`

**Background:** `vulnerability_list` is at line 366. It calls `latest_session_ids()` inside `base_qs` (line 393). You need to capture that queryset result into a local variable so you can reuse it for the 4 count queries without calling `latest_session_ids()` 4 extra times.

The function currently does:
```python
base_qs = Finding.objects.select_related("session")
if not session_id:
    base_qs = base_qs.filter(session_id__in=latest_session_ids())
```

`latest_session_ids()` is imported at top of file via `from apps.core.queries import latest_session_ids`. The 4 counts always use the latest sessions (they don't change based on `session_id` filter — the cards show global open counts).

- [ ] **Step 1: Write the failing tests**

Add a new class at the end of the `TestScanViews` class block (after `test_finding_list_only_latest_scan_per_domain`, around line 310). Open `tests/unit/test_scans.py` and add this class after the existing scan/finding view tests (before the `# Scheduling tests` comment at line 312):

```python
@pytest.mark.django_db
class TestFindingsPageCards:
    """Severity summary cards — count_open_* context variables."""

    def _make_session(self, domain="cards.com"):
        from apps.core.scans.models import ScanSession
        from django.utils import timezone
        return ScanSession.objects.create(
            domain=domain, scan_type="full", status="completed",
            end_time=timezone.now()
        )

    def _finding(self, session, severity, status="open"):
        from apps.core.findings.models import Finding
        return Finding.objects.create(
            session=session, source="domain_security", target=session.domain,
            check_type="dns", severity=severity, title=f"{severity} finding",
            description="d", remediation="r", status=status,
        )

    def test_count_vars_in_context(self, auth_client):
        resp = auth_client.get(reverse("finding-list"))
        assert resp.status_code == 200
        assert "count_open_critical" in resp.context
        assert "count_open_high" in resp.context
        assert "count_open_medium" in resp.context
        assert "count_open_low" in resp.context

    def test_count_open_critical_excludes_resolved(self, auth_client):
        session = self._make_session("excl-resolved.com")
        self._finding(session, "critical", status="resolved")
        resp = auth_client.get(reverse("finding-list"))
        assert resp.context["count_open_critical"] == 0

    def test_count_open_critical_excludes_acknowledged(self, auth_client):
        session = self._make_session("excl-ack.com")
        self._finding(session, "critical", status="acknowledged")
        resp = auth_client.get(reverse("finding-list"))
        assert resp.context["count_open_critical"] == 0

    def test_count_open_high_counts_correctly(self, auth_client):
        session = self._make_session("count-high.com")
        self._finding(session, "high")
        self._finding(session, "high")
        self._finding(session, "medium")
        resp = auth_client.get(reverse("finding-list"))
        assert resp.context["count_open_high"] == 2

    def test_severity_card_link_present(self, auth_client):
        resp = auth_client.get(reverse("finding-list"))
        assert b"?severity=critical" in resp.content
        assert b"?severity=high" in resp.content
        assert b"?severity=medium" in resp.content
        assert b"?severity=low" in resp.content

    def test_selected_card_has_ring(self, auth_client):
        resp = auth_client.get(reverse("finding-list") + "?severity=critical")
        assert b"ring-red-400" in resp.content
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/unit/test_scans.py::TestFindingsPageCards -v --ignore=tests/unit/test_domain_security.py
```

Expected: 6 failures — `KeyError: 'count_open_critical'` or similar.

- [ ] **Step 3: Add count queries to the view**

In `apps/core/scans/views.py`, modify `vulnerability_list` (line 366). The current code (lines 390–393):

```python
    # Default: restrict to latest completed session per domain (no duplicates across runs)
    base_qs = Finding.objects.select_related("session")
    if not session_id:
        base_qs = base_qs.filter(session_id__in=latest_session_ids())
```

Replace with:

```python
    # Default: restrict to latest completed session per domain (no duplicates across runs)
    latest_ids = latest_session_ids()
    base_qs = Finding.objects.select_related("session")
    if not session_id:
        base_qs = base_qs.filter(session_id__in=latest_ids)

    # Summary card counts — always across latest sessions, open status only
    count_open_critical = Finding.objects.filter(session_id__in=latest_ids, status="open", severity="critical").count()
    count_open_high     = Finding.objects.filter(session_id__in=latest_ids, status="open", severity="high").count()
    count_open_medium   = Finding.objects.filter(session_id__in=latest_ids, status="open", severity="medium").count()
    count_open_low      = Finding.objects.filter(session_id__in=latest_ids, status="open", severity="low").count()
```

Then update the full-page `render()` call at the bottom of the function (currently lines 423–431):

```python
    return render(request, "findings/list.html", {
        "vulns": vulns,
        "page_obj": page,
        "severity": severity,
        "session_id": session_id,
        "domain": domain,
        "status_filter": status_filter,
        "status_choices": STATUS_CHOICES,
        "count_open_critical": count_open_critical,
        "count_open_high": count_open_high,
        "count_open_medium": count_open_medium,
        "count_open_low": count_open_low,
    })
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/unit/test_scans.py::TestFindingsPageCards -v --ignore=tests/unit/test_domain_security.py
```

Expected: `test_count_vars_in_context`, `test_count_open_critical_excludes_resolved`, `test_count_open_critical_excludes_acknowledged`, `test_count_open_high_counts_correctly` all PASS. `test_severity_card_link_present` and `test_selected_card_has_ring` will still FAIL (template not updated yet).

- [ ] **Step 5: Run full test suite to check no regressions**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -q
```

Expected: Only the 2 template tests failing; all others PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/core/scans/views.py tests/unit/test_scans.py
git commit -m "feat(findings): add count_open_* context vars for severity cards"
```

---

## Task 2: Add severity summary cards to findings/list.html

**Spec ref:** Template Changes — `templates/findings/list.html`: add severity cards grid, remove Domain `<th>`.

**Files:**
- Modify: `templates/findings/list.html`

**Background:** The current template has a page heading (`<h1>`), a filter form card, and then the table card. The 4 severity cards go between the page heading and the filter form. Each card is an `<a>` tag linking to `?severity=X`. The selected card gets a colored ring — detected via `{% if severity == 'X' %}` using the `severity` context variable already present.

The Domain `<th>` is the 6th column header — remove it here. `vuln_rows.html` will remove the matching `<td>` in Task 3.

- [ ] **Step 1: Replace `templates/findings/list.html`**

Replace the entire file with:

```html
{% extends "base.html" %}

{% block title %}Findings{% endblock %}

{% block content %}
<h1 class="text-2xl font-bold text-gray-900 mb-4">Findings</h1>

<!-- Severity summary cards -->
<div class="grid grid-cols-4 gap-4 mb-4">
  <a href="?severity=critical{% if domain %}&domain={{ domain }}{% endif %}{% if status_filter %}&status={{ status_filter }}{% endif %}"
     class="bg-white border border-red-200 rounded-lg p-4 cursor-pointer hover:shadow-md transition-shadow {% if severity == 'critical' %}ring-2 ring-red-400{% endif %}">
    <div class="text-xs font-semibold text-red-500 uppercase tracking-wide">Critical</div>
    <div class="text-3xl font-bold text-red-600 my-1">{{ count_open_critical }}</div>
    <div class="text-xs text-slate-400">open findings</div>
  </a>
  <a href="?severity=high{% if domain %}&domain={{ domain }}{% endif %}{% if status_filter %}&status={{ status_filter }}{% endif %}"
     class="bg-white border border-orange-200 rounded-lg p-4 cursor-pointer hover:shadow-md transition-shadow {% if severity == 'high' %}ring-2 ring-orange-400{% endif %}">
    <div class="text-xs font-semibold text-orange-500 uppercase tracking-wide">High</div>
    <div class="text-3xl font-bold text-orange-600 my-1">{{ count_open_high }}</div>
    <div class="text-xs text-slate-400">open findings</div>
  </a>
  <a href="?severity=medium{% if domain %}&domain={{ domain }}{% endif %}{% if status_filter %}&status={{ status_filter }}{% endif %}"
     class="bg-white border border-yellow-200 rounded-lg p-4 cursor-pointer hover:shadow-md transition-shadow {% if severity == 'medium' %}ring-2 ring-yellow-400{% endif %}">
    <div class="text-xs font-semibold text-yellow-600 uppercase tracking-wide">Medium</div>
    <div class="text-3xl font-bold text-yellow-700 my-1">{{ count_open_medium }}</div>
    <div class="text-xs text-slate-400">open findings</div>
  </a>
  <a href="?severity=low{% if domain %}&domain={{ domain }}{% endif %}{% if status_filter %}&status={{ status_filter }}{% endif %}"
     class="bg-white border border-blue-200 rounded-lg p-4 cursor-pointer hover:shadow-md transition-shadow {% if severity == 'low' %}ring-2 ring-blue-400{% endif %}">
    <div class="text-xs font-semibold text-blue-500 uppercase tracking-wide">Low</div>
    <div class="text-3xl font-bold text-blue-600 my-1">{{ count_open_low }}</div>
    <div class="text-xs text-slate-400">open findings</div>
  </a>
</div>

<div class="bg-white rounded-lg shadow mb-4 px-6 py-4">
  <form class="flex gap-4 items-end"
        hx-get="{% url 'finding-list' %}"
        hx-target="#vuln-table-body"
        hx-trigger="change, input delay:400ms from:[name=domain]">
    <div class="flex-1">
      <label class="block text-xs font-medium text-gray-500 mb-1">Domain</label>
      <input type="text" name="domain" value="{{ domain }}" placeholder="Filter by domain"
             class="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500">
    </div>
    <div>
      <label class="block text-xs font-medium text-gray-500 mb-1">Severity</label>
      <select name="severity" class="px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500">
        <option value="">All</option>
        <option value="critical" {% if severity == "critical" %}selected{% endif %}>Critical</option>
        <option value="high" {% if severity == "high" %}selected{% endif %}>High</option>
        <option value="medium" {% if severity == "medium" %}selected{% endif %}>Medium</option>
        <option value="low" {% if severity == "low" %}selected{% endif %}>Low</option>
      </select>
    </div>
    <div>
      <label class="block text-xs font-medium text-gray-500 mb-1">Status</label>
      <select name="status" class="px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500">
        <option value="">All</option>
        {% for value, label in status_choices %}
        <option value="{{ value }}" {% if status_filter == value %}selected{% endif %}>{{ label }}</option>
        {% endfor %}
      </select>
    </div>
    {% if session_id %}
    <input type="hidden" name="session_id" value="{{ session_id }}">
    {% endif %}
  </form>
</div>

<div class="bg-white rounded-lg shadow overflow-hidden">
  <table class="min-w-full divide-y divide-gray-200">
    <thead class="bg-gray-50">
      <tr>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Title</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Host</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase"></th>
      </tr>
    </thead>
    <tbody id="vuln-table-body" class="bg-white divide-y divide-gray-200">
      {% include "partials/vuln_rows.html" %}
    </tbody>
  </table>
  {% include "partials/pagination.html" %}
</div>
{% endblock %}
```

- [ ] **Step 2: Run the two remaining failing tests**

```bash
uv run pytest tests/unit/test_scans.py::TestFindingsPageCards::test_severity_card_link_present tests/unit/test_scans.py::TestFindingsPageCards::test_selected_card_has_ring -v
```

Expected: Both PASS.

- [ ] **Step 3: Run full test suite**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -q
```

Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add templates/findings/list.html
git commit -m "feat(findings): add severity summary cards and remove domain column header"
```

---

## Task 3: Update vuln_rows.html — remove domain column, icon-ify scan link

**Spec ref:** Template Changes — `templates/partials/vuln_rows.html`: remove domain `<td>`, replace scan link text with ↗ icon, fix colspan.

**Files:**
- Modify: `templates/partials/vuln_rows.html`

**Background:** This partial is rendered both on full page load and on HTMX partial refresh. Removing the domain `<td>` (column 6) and updating colspan from 7 to 6 keeps it consistent with the table header changed in Task 2.

- [ ] **Step 1: Replace `templates/partials/vuln_rows.html`**

Replace the entire file with:

```html
{% for vuln in vulns %}
<tr class="hover:bg-gray-50">
  <td class="px-6 py-4 text-sm text-gray-900">{{ vuln.title }}</td>
  <td class="px-6 py-4 text-sm font-mono text-gray-500">{{ vuln.host }}</td>
  <td class="px-6 py-4 text-sm">
    {% include "partials/severity_badge.html" with severity=vuln.severity %}
  </td>
  <td class="px-6 py-4 text-sm text-gray-500">{{ vuln.source|upper }}</td>
  <td class="px-6 py-4 text-sm" id="finding-status-{{ vuln.obj.id }}">
    {% include "partials/finding_status_cell.html" with finding=vuln.obj %}
  </td>
  <td class="px-6 py-4 text-sm text-center">
    <a href="{% url 'scan-detail' vuln.session.uuid %}" class="text-indigo-500 hover:text-indigo-700" title="View scan">↗</a>
  </td>
</tr>
{% empty %}
<tr>
  <td colspan="6" class="px-6 py-8 text-center text-gray-400 text-sm">No findings found.</td>
</tr>
{% endfor %}
```

- [ ] **Step 2: Run full test suite**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -q
```

Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add templates/partials/vuln_rows.html
git commit -m "feat(findings): remove domain column, replace scan link with icon"
```
