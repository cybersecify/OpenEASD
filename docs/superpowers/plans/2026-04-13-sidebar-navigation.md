# Sidebar Navigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the horizontal top navbar with a slate-black sidebar that shows a red badge for open critical/high findings and a pulsing dot when a scan is running.

**Architecture:** A Django context processor (`sidebar_counts`) injects two counts into every template via `settings.py`. `base.html` is rewritten to use a flex layout with a fixed-width sidebar on the left and the main content on the right. Active state is detected using `request.resolver_match.url_name` inside the template.

**Tech Stack:** Django context processors, Tailwind CSS (CDN), existing Alpine.js and HTMX (unchanged).

**Spec:** `docs/superpowers/specs/2026-04-13-sidebar-navigation-design.md`

---

## File Map

| File | Change |
|---|---|
| `apps/core/dashboard/context_processors.py` | Create — `sidebar_counts(request)` function |
| `openeasd/settings.py` | Register context processor in `TEMPLATES[0]["OPTIONS"]["context_processors"]` |
| `templates/base.html` | Replace top navbar with sidebar layout |
| `tests/unit/test_core.py` | Add `TestSidebarCountsContextProcessor` class |

---

## Task 1: `sidebar_counts` Context Processor

**Files:**
- Create: `apps/core/dashboard/context_processors.py`
- Test: `tests/unit/test_core.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/test_core.py` after the existing test classes:

```python
@pytest.mark.django_db
class TestSidebarCountsContextProcessor:
    def _call(self):
        from apps.core.dashboard.context_processors import sidebar_counts
        return sidebar_counts(None)  # request is not used

    def test_returns_zero_badge_when_no_findings(self, db):
        result = self._call()
        assert result["sidebar_finding_badge"] == 0

    def test_counts_open_critical_findings(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        session = ScanSession.objects.create(domain="example.com", scan_type="full")
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="critical", title="CVE-2024-0001",
            status="open",
        )
        result = self._call()
        assert result["sidebar_finding_badge"] == 1

    def test_counts_open_high_findings(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        session = ScanSession.objects.create(domain="example.com", scan_type="full")
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="high", title="CVE-2024-0002",
            status="open",
        )
        result = self._call()
        assert result["sidebar_finding_badge"] == 1

    def test_badge_sums_critical_and_high(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        session = ScanSession.objects.create(domain="example.com", scan_type="full")
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="critical", title="CVE-A", status="open",
        )
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="high", title="CVE-B", status="open",
        )
        result = self._call()
        assert result["sidebar_finding_badge"] == 2

    def test_does_not_count_non_open_findings(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        session = ScanSession.objects.create(domain="example.com", scan_type="full")
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="critical", title="CVE-A",
            status="acknowledged",
        )
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="critical", title="CVE-B",
            status="resolved",
        )
        result = self._call()
        assert result["sidebar_finding_badge"] == 0

    def test_does_not_count_medium_or_low_findings(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        session = ScanSession.objects.create(domain="example.com", scan_type="full")
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="medium", title="Med", status="open",
        )
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="low", title="Low", status="open",
        )
        result = self._call()
        assert result["sidebar_finding_badge"] == 0

    def test_returns_zero_running_when_no_scans(self, db):
        result = self._call()
        assert result["sidebar_running_count"] == 0

    def test_counts_running_scans(self, db):
        from apps.core.scans.models import ScanSession
        ScanSession.objects.create(domain="example.com", scan_type="full", status="running")
        result = self._call()
        assert result["sidebar_running_count"] == 1

    def test_does_not_count_non_running_scans(self, db):
        from apps.core.scans.models import ScanSession
        ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
        ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")
        result = self._call()
        assert result["sidebar_running_count"] == 0
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/unit/test_core.py::TestSidebarCountsContextProcessor -v
```

Expected: `ImportError` — `context_processors` module does not exist yet.

- [ ] **Step 3: Create the context processor**

Create `apps/core/dashboard/context_processors.py`:

```python
from apps.core.findings.models import Finding
from apps.core.scans.models import ScanSession


def sidebar_counts(request):
    """
    Inject sidebar badge counts into every template context.

    sidebar_finding_badge  — count of open critical+high findings
    sidebar_running_count  — count of currently running scan sessions
    """
    finding_badge = Finding.objects.filter(
        severity__in=["critical", "high"],
        status="open",
    ).count()

    running_count = ScanSession.objects.filter(status="running").count()

    return {
        "sidebar_finding_badge": finding_badge,
        "sidebar_running_count": running_count,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/unit/test_core.py::TestSidebarCountsContextProcessor -v
```

Expected: 9 PASSED.

- [ ] **Step 5: Commit**

```bash
git add apps/core/dashboard/context_processors.py tests/unit/test_core.py
git commit -m "feat(sidebar): add sidebar_counts context processor"
```

---

## Task 2: Register Context Processor in Settings

**Files:**
- Modify: `openeasd/settings.py` (lines 77–82)

No new tests needed — Django raises `ImproperlyConfigured` at startup if the dotted path is wrong, which the next task's manual test will catch.

- [ ] **Step 1: Add the context processor to `TEMPLATES`**

In `openeasd/settings.py`, find the `context_processors` list (currently at line 77) and add the new entry:

```python
"context_processors": [
    "django.template.context_processors.debug",
    "django.template.context_processors.request",
    "django.contrib.auth.context_processors.auth",
    "django.contrib.messages.context_processors.messages",
    "apps.core.dashboard.context_processors.sidebar_counts",
],
```

- [ ] **Step 2: Verify Django starts without errors**

```bash
uv run manage.py check
```

Expected output: `System check identified no issues (0 silenced).`

- [ ] **Step 3: Commit**

```bash
git add openeasd/settings.py
git commit -m "feat(sidebar): register sidebar_counts context processor"
```

---

## Task 3: Rewrite `base.html` — Sidebar Layout

**Files:**
- Modify: `templates/base.html`

- [ ] **Step 1: Write the integration tests**

Add to `tests/unit/test_core.py` inside `TestDashboardView`:

```python
    def test_sidebar_present_in_dashboard(self, auth_client):
        resp = auth_client.get(reverse("dashboard"))
        assert b"OpenEASD" in resp.content
        assert b"Findings" in resp.content
        assert b"Workflows" in resp.content
        assert b"Logout" in resp.content

    def test_sidebar_badge_shown_when_critical_findings(self, auth_client, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        session = ScanSession.objects.create(domain="example.com", scan_type="full")
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4",
            check_type="cve", severity="critical", title="CVE-X", status="open",
        )
        resp = auth_client.get(reverse("dashboard"))
        # The badge count should appear in the response
        assert b"bg-red-600" in resp.content

    def test_sidebar_running_indicator_shown_when_scan_running(self, auth_client, db):
        from apps.core.scans.models import ScanSession
        ScanSession.objects.create(domain="example.com", scan_type="full", status="running")
        resp = auth_client.get(reverse("dashboard"))
        assert b"animate-pulse" in resp.content
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/unit/test_core.py::TestDashboardView::test_sidebar_present_in_dashboard tests/unit/test_core.py::TestDashboardView::test_sidebar_badge_shown_when_critical_findings tests/unit/test_core.py::TestDashboardView::test_sidebar_running_indicator_shown_when_scan_running -v
```

Expected: `test_sidebar_badge_shown_when_critical_findings` and `test_sidebar_running_indicator_shown_when_scan_running` FAIL (old template has no sidebar markup).

- [ ] **Step 3: Replace `templates/base.html` entirely**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{% block title %}OpenEASD{% endblock %} — Attack Surface Detection</title>
  <script src="https://unpkg.com/htmx.org@2.0.4" integrity="sha384-HGfztofotfshcF7+8n44JQL2oJmowVChPTg48S+jvZoztPfvwD79OC/LTtG6dMp+" crossorigin="anonymous"></script>
  <script src="https://cdn.jsdelivr.net/npm/alpinejs@3.14.1/dist/cdn.min.js" defer></script>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>[x-cloak] { display: none !important; }</style>
</head>
<body class="bg-gray-50 text-gray-900 min-h-screen flex">

  <!-- Sidebar -->
  <aside class="w-56 bg-slate-900 flex flex-col min-h-screen flex-shrink-0">

    <!-- Logo -->
    <div class="px-4 py-4 border-b border-slate-800">
      <a href="{% url 'dashboard' %}" class="font-bold text-white text-sm tracking-tight">⬡ OpenEASD</a>
    </div>

    <!-- Nav links -->
    {% with n=request.resolver_match.url_name %}
    <nav class="flex-1 py-2">

      <a href="{% url 'dashboard' %}"
         class="flex items-center gap-2 px-4 py-2 text-sm border-l-2
           {% if n == 'dashboard' %}bg-slate-800 text-white border-indigo-500
           {% else %}text-slate-500 hover:text-slate-300 hover:bg-slate-800/50 border-transparent{% endif %}">
        Dashboard
      </a>

      <a href="{% url 'domain-list' %}"
         class="flex items-center gap-2 px-4 py-2 text-sm border-l-2
           {% if n == 'domain-list' or n == 'domain-toggle' or n == 'domain-delete' %}bg-slate-800 text-white border-indigo-500
           {% else %}text-slate-500 hover:text-slate-300 hover:bg-slate-800/50 border-transparent{% endif %}">
        Domains
      </a>

      <a href="{% url 'scan-list' %}"
         class="flex items-center justify-between px-4 py-2 text-sm border-l-2
           {% if n == 'scan-list' or n == 'scan-detail' or n == 'scan-start' or n == 'scan-status-fragment' or n == 'scan-stop' or n == 'scan-delete' or n == 'scheduled-jobs' %}bg-slate-800 text-white border-indigo-500
           {% else %}text-slate-500 hover:text-slate-300 hover:bg-slate-800/50 border-transparent{% endif %}">
        <span>Scans</span>
        {% if sidebar_running_count > 0 %}
        <span class="flex items-center gap-1 text-xs text-blue-400">
          <span class="w-1.5 h-1.5 bg-blue-500 rounded-full animate-pulse inline-block"></span>{{ sidebar_running_count }}
        </span>
        {% endif %}
      </a>

      <a href="{% url 'finding-list' %}"
         class="flex items-center justify-between px-4 py-2 text-sm border-l-2
           {% if n == 'finding-list' or n == 'finding-update-status' %}bg-slate-800 text-white border-indigo-500
           {% else %}text-slate-500 hover:text-slate-300 hover:bg-slate-800/50 border-transparent{% endif %}">
        <span>Findings</span>
        {% if sidebar_finding_badge > 0 %}
        <span class="bg-red-600 text-white text-xs font-bold px-1.5 py-0.5 rounded-full leading-none">{{ sidebar_finding_badge }}</span>
        {% endif %}
      </a>

      <a href="{% url 'insights' %}"
         class="flex items-center gap-2 px-4 py-2 text-sm border-l-2
           {% if n == 'insights' %}bg-slate-800 text-white border-indigo-500
           {% else %}text-slate-500 hover:text-slate-300 hover:bg-slate-800/50 border-transparent{% endif %}">
        Insights
      </a>

      <a href="{% url 'workflow-list' %}"
         class="flex items-center gap-2 px-4 py-2 text-sm border-l-2
           {% if n == 'workflow-list' or n == 'workflow-create' or n == 'workflow-detail' or n == 'workflow-delete' or n == 'workflow-toggle-step' %}bg-slate-800 text-white border-indigo-500
           {% else %}text-slate-500 hover:text-slate-300 hover:bg-slate-800/50 border-transparent{% endif %}">
        Workflows
      </a>

    </nav>
    {% endwith %}

    <!-- Logout -->
    <div class="px-4 py-3 border-t border-slate-800">
      <form method="post" action="{% url 'logout' %}">
        {% csrf_token %}
        <button type="submit" class="text-slate-500 hover:text-slate-300 text-xs font-medium">Logout</button>
      </form>
    </div>

  </aside>

  <!-- Main content -->
  <div class="flex-1 flex flex-col min-h-screen">
    <main class="flex-1 px-8 py-8">
      <div class="max-w-7xl mx-auto">

        {% if messages %}
        <div class="mb-6 space-y-2">
          {% for message in messages %}
          <div x-data="{ show: true }" x-show="show" x-init="setTimeout(() => show = false, 5000)"
               class="px-4 py-3 rounded-lg text-sm flex items-center justify-between
                 {% if message.tags == 'success' %}bg-green-50 border border-green-200 text-green-700
                 {% elif message.tags == 'error' %}bg-red-50 border border-red-200 text-red-700
                 {% elif message.tags == 'warning' %}bg-yellow-50 border border-yellow-200 text-yellow-700
                 {% else %}bg-blue-50 border border-blue-200 text-blue-700{% endif %}">
            <span>{{ message }}</span>
            <button @click="show = false" class="text-gray-400 hover:text-gray-600 ml-4">&times;</button>
          </div>
          {% endfor %}
        </div>
        {% endif %}

        {% block content %}{% endblock %}

      </div>
    </main>
  </div>

</body>
</html>
```

- [ ] **Step 4: Run the three new tests**

```bash
uv run pytest tests/unit/test_core.py::TestDashboardView::test_sidebar_present_in_dashboard tests/unit/test_core.py::TestDashboardView::test_sidebar_badge_shown_when_critical_findings tests/unit/test_core.py::TestDashboardView::test_sidebar_running_indicator_shown_when_scan_running -v
```

Expected: 3 PASSED.

- [ ] **Step 5: Run full test suite to check no regressions**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all PASSED.

- [ ] **Step 6: Commit**

```bash
git add templates/base.html tests/unit/test_core.py
git commit -m "feat(sidebar): replace top navbar with slate-black sidebar layout"
```
