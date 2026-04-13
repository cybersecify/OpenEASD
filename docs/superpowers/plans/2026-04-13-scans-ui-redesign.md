# Scans Page UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 3 clickable status summary cards (Running/Completed/Failed) to the top of the scans page and replace the "Started" column with a "When" column showing start time plus a duration sub-line.

**Architecture:** Two changes in parallel: (1) a new `scan_duration_label` template filter in a new `templatetags` package computes the duration string per scan; (2) the view adds 3 count context variables for the status cards. Templates wire them together.

**Tech Stack:** Django 5+, Tailwind CSS (CDN), existing `ScanSession` model (`start_time`, `end_time`, `status` fields).

---

## File Map

| File | Change |
|---|---|
| `apps/core/scans/templatetags/__init__.py` | Create — empty, makes templatetags a package |
| `apps/core/scans/templatetags/scan_tags.py` | Create — `scan_duration_label` filter |
| `apps/core/scans/views.py` | Modify — add 3 `count_*` vars to full-page render (lines 141–176) |
| `templates/scans/list.html` | Modify — add status cards grid, replace Started `<th>` with When |
| `templates/partials/scan_rows.html` | Modify — load scan_tags, replace Started `<td>` with When cell |
| `tests/unit/test_scans.py` | Modify — add `TestScanDurationLabel` and `TestScanListCards` classes |

---

## Task 1: scan_duration_label template filter

**Spec ref:** New file `apps/core/scans/templatetags/scan_tags.py` — `scan_duration_label` filter.

**Files:**
- Create: `apps/core/scans/templatetags/__init__.py`
- Create: `apps/core/scans/templatetags/scan_tags.py`
- Test: `tests/unit/test_scans.py`

**Background:** Django requires a `templatetags/` directory inside an app to be a Python package (needs `__init__.py`). The filter receives a `ScanSession` object and returns a human-readable duration string. It uses `django.utils.timezone.now()` for running scans so it's testable with mocking.

- [ ] **Step 1: Write the failing tests**

Find the `TestScanViews` class in `tests/unit/test_scans.py`. Add the following new class **before** it (i.e., before line 226):

```python
class TestScanDurationLabel:
    """Unit tests for the scan_duration_label template filter."""

    def _make_scan(self, status, start_offset_seconds=-300, end_offset_seconds=None):
        """Build a mock ScanSession without hitting the DB."""
        from unittest.mock import MagicMock
        from django.utils import timezone
        import datetime
        scan = MagicMock()
        scan.status = status
        scan.start_time = timezone.now() - datetime.timedelta(seconds=abs(start_offset_seconds))
        if end_offset_seconds is not None:
            scan.end_time = scan.start_time + datetime.timedelta(seconds=end_offset_seconds)
        else:
            scan.end_time = None
        return scan

    def test_completed_scan_returns_took(self):
        from apps.core.scans.templatetags.scan_tags import scan_duration_label
        scan = self._make_scan("completed", end_offset_seconds=492)  # 8m 12s
        result = scan_duration_label(scan)
        assert result == "took 8m 12s"

    def test_failed_scan_returns_after(self):
        from apps.core.scans.templatetags.scan_tags import scan_duration_label
        scan = self._make_scan("failed", end_offset_seconds=63)  # 1m 03s
        result = scan_duration_label(scan)
        assert result == "after 1m 03s"

    def test_running_scan_returns_running(self):
        from apps.core.scans.templatetags.scan_tags import scan_duration_label
        import datetime
        from unittest.mock import patch
        from django.utils import timezone
        scan = self._make_scan("running", start_offset_seconds=221)  # 3m 41s ago
        fixed_now = scan.start_time + datetime.timedelta(seconds=221)
        with patch("apps.core.scans.templatetags.scan_tags.timezone") as mock_tz:
            mock_tz.now.return_value = fixed_now
            result = scan_duration_label(scan)
        assert result == "running 3m 41s"

    def test_pending_scan_returns_empty(self):
        from apps.core.scans.templatetags.scan_tags import scan_duration_label
        scan = self._make_scan("pending")
        result = scan_duration_label(scan)
        assert result == ""

    def test_no_end_time_returns_empty(self):
        from apps.core.scans.templatetags.scan_tags import scan_duration_label
        scan = self._make_scan("completed", end_offset_seconds=None)
        result = scan_duration_label(scan)
        assert result == ""

    def test_sub_minute_duration(self):
        from apps.core.scans.templatetags.scan_tags import scan_duration_label
        scan = self._make_scan("completed", end_offset_seconds=45)
        result = scan_duration_label(scan)
        assert result == "took 45s"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/unit/test_scans.py::TestScanDurationLabel -v --ignore=tests/unit/test_domain_security.py
```

Expected: ImportError — `apps.core.scans.templatetags.scan_tags` not found.

- [ ] **Step 3: Create the templatetags package**

Create `apps/core/scans/templatetags/__init__.py` (empty file).

- [ ] **Step 4: Create the filter**

Create `apps/core/scans/templatetags/scan_tags.py`:

```python
from django import template
from django.utils import timezone

register = template.Library()


@register.filter
def scan_duration_label(scan):
    """Return a human-readable duration string for the scan's When column.

    - running  → "running Xm Ys"  (elapsed since start, at render time)
    - completed → "took Xm Ys"
    - failed    → "after Xm Ys"
    - others    → "" (no sub-line shown)
    """
    if scan.status == "running":
        delta = timezone.now() - scan.start_time
        prefix = "running"
    elif scan.status in ("completed", "failed") and scan.end_time:
        delta = scan.end_time - scan.start_time
        prefix = "took" if scan.status == "completed" else "after"
    else:
        return ""

    total_seconds = int(delta.total_seconds())
    minutes, seconds = divmod(total_seconds, 60)
    if minutes:
        return f"{prefix} {minutes}m {seconds:02d}s"
    return f"{prefix} {seconds}s"
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
uv run pytest tests/unit/test_scans.py::TestScanDurationLabel -v --ignore=tests/unit/test_domain_security.py
```

Expected: 6 PASS.

- [ ] **Step 6: Run full suite to check no regressions**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -q
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add apps/core/scans/templatetags/__init__.py apps/core/scans/templatetags/scan_tags.py tests/unit/test_scans.py
git commit -m "feat(scans): add scan_duration_label template filter"
```

---

## Task 2: Add count_* context variables to scan_list view

**Spec ref:** View changes — `count_running`, `count_completed`, `count_failed` added to full-page render context only.

**Files:**
- Modify: `apps/core/scans/views.py:141–176`
- Test: `tests/unit/test_scans.py`

**Background:** `scan_list` is at line 142. The full-page render is at line 171. The HTMX partial render at line 157 must NOT get the count vars (cards are not in the partial). `ScanSession` is already imported at the top of views.py.

- [ ] **Step 1: Write the failing tests**

Add the following class to `tests/unit/test_scans.py`, right before the `# Scheduling tests` comment block:

```python
@pytest.mark.django_db
class TestScanListCards:
    """Status summary cards — count_* context variables."""

    def _make_session(self, status, domain="cards-scan.com"):
        from apps.core.scans.models import ScanSession
        from django.utils import timezone
        return ScanSession.objects.create(
            domain=domain, scan_type="full", status=status,
            end_time=timezone.now() if status in ("completed", "failed") else None,
        )

    def test_count_vars_in_context(self, auth_client):
        resp = auth_client.get(reverse("scan-list"))
        assert resp.status_code == 200
        assert "count_running" in resp.context
        assert "count_completed" in resp.context
        assert "count_failed" in resp.context

    def test_count_running_counts_correctly(self, auth_client):
        baseline_resp = auth_client.get(reverse("scan-list"))
        baseline = baseline_resp.context["count_running"]
        self._make_session("running", domain="r1.com")
        self._make_session("running", domain="r2.com")
        resp = auth_client.get(reverse("scan-list"))
        assert resp.context["count_running"] == baseline + 2

    def test_count_completed_excludes_running(self, auth_client):
        baseline_resp = auth_client.get(reverse("scan-list"))
        baseline = baseline_resp.context["count_completed"]
        self._make_session("running", domain="running-excluded.com")
        resp = auth_client.get(reverse("scan-list"))
        assert resp.context["count_completed"] == baseline

    def test_status_card_links_present(self, auth_client):
        resp = auth_client.get(reverse("scan-list"))
        assert b"?status=running" in resp.content
        assert b"?status=completed" in resp.content
        assert b"?status=failed" in resp.content

    def test_selected_card_has_ring(self, auth_client):
        resp = auth_client.get(reverse("scan-list") + "?status=completed")
        assert b"ring-green-400" in resp.content
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/unit/test_scans.py::TestScanListCards -v --ignore=tests/unit/test_domain_security.py
```

Expected: `KeyError: 'count_running'` or similar for context tests; content tests fail because template not updated yet.

- [ ] **Step 3: Add count queries to the view**

In `apps/core/scans/views.py`, modify `scan_list` (line 142). The current render block (lines 171–176) is:

```python
    return render(request, "scans/list.html", {
        "scans": page,
        "domain": domain,
        "status_filter": status_filter,
        "scheduled": scheduled,
    })
```

Replace with:

```python
    count_running   = ScanSession.objects.filter(status="running").count()
    count_completed = ScanSession.objects.filter(status="completed").count()
    count_failed    = ScanSession.objects.filter(status="failed").count()

    return render(request, "scans/list.html", {
        "scans": page,
        "domain": domain,
        "status_filter": status_filter,
        "scheduled": scheduled,
        "count_running": count_running,
        "count_completed": count_completed,
        "count_failed": count_failed,
    })
```

- [ ] **Step 4: Run the 3 context tests (card link + ring tests still fail — expected)**

```bash
uv run pytest tests/unit/test_scans.py::TestScanListCards::test_count_vars_in_context tests/unit/test_scans.py::TestScanListCards::test_count_running_counts_correctly tests/unit/test_scans.py::TestScanListCards::test_count_completed_excludes_running -v --ignore=tests/unit/test_domain_security.py
```

Expected: 3 PASS.

- [ ] **Step 5: Run full suite**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -q
```

Expected: only `test_status_card_links_present` and `test_selected_card_has_ring` fail.

- [ ] **Step 6: Commit**

```bash
git add apps/core/scans/views.py tests/unit/test_scans.py
git commit -m "feat(scans): add count_running/completed/failed context vars for status cards"
```

---

## Task 3: Add status cards and When column to templates

**Spec ref:** Template changes — `templates/scans/list.html` (cards + When `<th>`) and `templates/partials/scan_rows.html` (When `<td>`).

**Files:**
- Modify: `templates/scans/list.html`
- Modify: `templates/partials/scan_rows.html`

**Background:** The cards go above the `{% if scheduled %}` block. Each card links to `?status=X` and preserves the existing `domain` filter (use `|urlencode`). The "Started" `<th>` at line 111 of `list.html` becomes "When". In `scan_rows.html`, the Started `<td>` at line 17 becomes a two-line When cell. `{% load scan_tags %}` must be at the top of `scan_rows.html`.

- [ ] **Step 1: Replace `templates/scans/list.html`**

Replace the entire file:

```html
{% extends "base.html" %}

{% block title %}Scans{% endblock %}

{% block content %}
<div class="mb-4">
  <h1 class="text-2xl font-bold text-gray-900">Scans</h1>
  <p class="text-gray-500 text-sm mt-1">Scan history and scheduled jobs</p>
</div>

<!-- Status summary cards -->
<div class="grid grid-cols-3 gap-4 mb-4">
  <a href="?status=running{% if domain %}&domain={{ domain|urlencode }}{% endif %}"
     class="bg-white border border-blue-200 rounded-lg p-4 cursor-pointer hover:shadow-md transition-shadow {% if status_filter == 'running' %}ring-2 ring-blue-400{% endif %}">
    <div class="text-xs font-semibold text-blue-500 uppercase tracking-wide">Running</div>
    <div class="text-3xl font-bold text-blue-600 my-1">{{ count_running }}</div>
    <div class="text-xs text-slate-400">active scans</div>
  </a>
  <a href="?status=completed{% if domain %}&domain={{ domain|urlencode }}{% endif %}"
     class="bg-white border border-green-200 rounded-lg p-4 cursor-pointer hover:shadow-md transition-shadow {% if status_filter == 'completed' %}ring-2 ring-green-400{% endif %}">
    <div class="text-xs font-semibold text-green-600 uppercase tracking-wide">Completed</div>
    <div class="text-3xl font-bold text-green-700 my-1">{{ count_completed }}</div>
    <div class="text-xs text-slate-400">finished scans</div>
  </a>
  <a href="?status=failed{% if domain %}&domain={{ domain|urlencode }}{% endif %}"
     class="bg-white border border-red-200 rounded-lg p-4 cursor-pointer hover:shadow-md transition-shadow {% if status_filter == 'failed' %}ring-2 ring-red-400{% endif %}">
    <div class="text-xs font-semibold text-red-500 uppercase tracking-wide">Failed</div>
    <div class="text-3xl font-bold text-red-600 my-1">{{ count_failed }}</div>
    <div class="text-xs text-slate-400">errored scans</div>
  </a>
</div>

<!-- Scheduled Jobs (shown only if any exist) -->
{% if scheduled %}
<div class="bg-white rounded-lg shadow mb-6">
  <div class="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
    <div>
      <h2 class="font-semibold text-gray-700">Scheduled Jobs</h2>
      <p class="text-xs text-gray-400 mt-0.5">Pending one-time and recurring scans</p>
    </div>
  </div>
  <table class="min-w-full divide-y divide-gray-100">
    <thead class="bg-gray-50">
      <tr>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Domain</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Next Run (IST)</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Frequency</th>
        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Actions</th>
      </tr>
    </thead>
    <tbody class="divide-y divide-gray-100">
      {% for job in scheduled %}
      <tbody x-data="{ confirmCancel: false }">
      <tr class="hover:bg-gray-50">
        <td class="px-6 py-3 text-sm font-mono font-medium text-gray-900">{{ job.domain }}</td>
        <td class="px-6 py-3 text-sm">
          {% if job.job_type == "recurring" %}
          <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-indigo-100 text-indigo-700">Recurring</span>
          {% else %}
          <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-100 text-amber-700">One-time</span>
          {% endif %}
        </td>
        <td class="px-6 py-3 text-sm text-gray-500">
          {% if job.next_run_time %}{{ job.next_run_time|date:"M d, Y H:i" }}{% else %}<span class="text-gray-300 italic">—</span>{% endif %}
        </td>
        <td class="px-6 py-3 text-sm text-gray-500">{{ job.frequency }}</td>
        <td class="px-6 py-3 text-right">
          <button @click="confirmCancel = true" x-show="!confirmCancel" class="text-red-500 hover:text-red-700 text-sm">Cancel</button>
        </td>
      </tr>
      <tr x-show="confirmCancel" x-cloak class="bg-red-50">
        <td colspan="5" class="px-6 py-3">
          <div class="flex items-center justify-between">
            <p class="text-sm text-red-700">Cancel scheduled scan for <span class="font-bold">{{ job.domain }}</span>?</p>
            <div class="flex items-center gap-3">
              <button @click="confirmCancel = false" class="text-sm text-gray-600 hover:text-gray-800">No, keep</button>
              <form method="post" action="{% url 'cancel-scheduled-job' job.job_id %}">
                {% csrf_token %}
                <button type="submit" class="px-3 py-1.5 bg-red-600 text-white text-sm rounded-md hover:bg-red-700">Yes, cancel</button>
              </form>
            </div>
          </div>
        </td>
      </tr>
      </tbody>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}

<!-- Filters -->
<div class="bg-white rounded-lg shadow mb-4 px-6 py-4">
  <form class="flex gap-4 items-end"
        hx-get="{% url 'scan-list' %}"
        hx-target="#scan-table-body"
        hx-trigger="change, input delay:400ms from:[name=domain]">
    <div class="flex-1">
      <label class="block text-xs font-medium text-gray-500 mb-1">Domain</label>
      <input type="text" name="domain" value="{{ domain }}" placeholder="Filter by domain"
             class="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500">
    </div>
    <div>
      <label class="block text-xs font-medium text-gray-500 mb-1">Status</label>
      <select name="status" class="px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500">
        <option value="">All</option>
        <option value="pending" {% if status_filter == "pending" %}selected{% endif %}>Pending</option>
        <option value="running" {% if status_filter == "running" %}selected{% endif %}>Running</option>
        <option value="completed" {% if status_filter == "completed" %}selected{% endif %}>Completed</option>
        <option value="cancelled" {% if status_filter == "cancelled" %}selected{% endif %}>Cancelled</option>
        <option value="failed" {% if status_filter == "failed" %}selected{% endif %}>Failed</option>
      </select>
    </div>
    <div class="shrink-0 self-end">
      <a href="{% url 'scan-list' %}" class="text-xs text-gray-400 hover:text-gray-600">Clear filters</a>
    </div>
  </form>
</div>

<!-- Scan History -->
<div class="bg-white rounded-lg shadow overflow-hidden">
  <div class="px-6 py-4 border-b border-gray-200">
    <h2 class="font-semibold text-gray-700">Scan History</h2>
  </div>
  <table class="min-w-full divide-y divide-gray-200">
    <thead class="bg-gray-50">
      <tr>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Domain</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Findings</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">When</th>
        <th class="px-6 py-3"></th>
      </tr>
    </thead>
    <tbody id="scan-table-body" class="bg-white divide-y divide-gray-200">
      {% include "partials/scan_rows.html" %}
    </tbody>
  </table>
  {% with page_obj=scans %}{% include "partials/pagination.html" %}{% endwith %}
</div>
{% endblock %}
```

- [ ] **Step 2: Replace `templates/partials/scan_rows.html`**

Replace the entire file:

```html
{% load scan_tags %}
{% for scan in scans %}
<tbody x-data="{ confirmDelete: false }">
<tr class="hover:bg-gray-50">
  <td class="px-6 py-4 text-sm font-medium text-gray-900">{{ scan.domain }}</td>
  <td class="px-6 py-4 text-sm text-gray-500">
    <span class="capitalize">{{ scan.scan_type }}</span>
    {% if scan.triggered_by == "scheduled" %}
    <span class="ml-1.5 inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-amber-100 text-amber-700">Scheduled</span>
    {% elif scan.triggered_by == "recurring" %}
    <span class="ml-1.5 inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-indigo-100 text-indigo-700">Recurring</span>
    {% endif %}
  </td>
  <td class="px-6 py-4 text-sm">
    {% include "partials/status_badge.html" with status=scan.status %}
  </td>
  <td class="px-6 py-4 text-sm text-gray-900">{{ scan.total_findings }}</td>
  <td class="px-6 py-4 text-sm">
    <div class="text-gray-500">{{ scan.start_time|date:"M d, Y H:i" }}</div>
    {% with label=scan|scan_duration_label %}
    {% if label %}<div class="text-xs text-slate-400">{{ label }}</div>{% endif %}
    {% endwith %}
  </td>
  <td class="px-6 py-4 text-right">
    <span x-show="!confirmDelete" class="flex items-center justify-end gap-3">
      <a href="{% url 'scan-detail' scan.uuid %}" class="text-indigo-600 hover:underline text-sm">View</a>
      <button @click="confirmDelete = true" class="text-red-500 hover:text-red-700 text-sm">Delete</button>
    </span>
  </td>
</tr>
<tr x-show="confirmDelete" x-cloak class="bg-red-50">
  <td colspan="6" class="px-6 py-3">
    <div class="flex items-center justify-between">
      <p class="text-sm text-red-700">
        Delete <span class="font-bold">{{ scan.domain }}</span> scan? This will remove all findings and assets.
      </p>
      <div class="flex items-center gap-3">
        <button @click="confirmDelete = false" class="text-sm text-gray-600 hover:text-gray-800">Cancel</button>
        <form method="post" action="{% url 'scan-delete' scan.uuid %}">
          {% csrf_token %}
          <button type="submit" class="px-3 py-1.5 bg-red-600 text-white text-sm rounded-md hover:bg-red-700">Yes, delete</button>
        </form>
      </div>
    </div>
  </td>
</tr>
</tbody>
{% empty %}
<tr>
  <td colspan="6" class="px-6 py-8 text-center text-gray-400 text-sm">No scans found.</td>
</tr>
{% endfor %}
```

- [ ] **Step 3: Run the 2 remaining failing tests**

```bash
uv run pytest tests/unit/test_scans.py::TestScanListCards::test_status_card_links_present tests/unit/test_scans.py::TestScanListCards::test_selected_card_has_ring -v --ignore=tests/unit/test_domain_security.py
```

Expected: both PASS.

- [ ] **Step 4: Run full test suite**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -q
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add templates/scans/list.html templates/partials/scan_rows.html
git commit -m "feat(scans): add status summary cards and When column with duration"
```
