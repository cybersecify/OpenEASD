# Domains Page UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the "Added" column in the domains table with "Last Scan" (date + status) and "Findings" (non-zero severity badges from the latest completed scan).

**Architecture:** Add a `_enrich_domains()` helper in the domains view that attaches `last_scan` and `findings_summary` to each `Domain` object. The template then uses these attributes directly. No new models, no new templatetags — two files only.

**Tech Stack:** Django 5, Tailwind CSS CDN, pytest-django

---

## File Map

| File | Change |
|---|---|
| `apps/core/domains/views.py` | Add `_enrich_domains()`, call it in `domain_list` and `domain_delete` error path |
| `templates/domains/list.html` | Replace Added `<th>`/`<td>` with Last Scan + Findings columns, colspan 5→6 |
| `tests/unit/test_domains.py` | New class `TestDomainListEnrichment` (9 tests) |

---

## Task 1: Domain enrichment helper

**Files:**
- Modify: `apps/core/domains/views.py`
- Test: `tests/unit/test_domains.py`

- [ ] **Step 1: Write failing tests for `_enrich_domains`**

Add this class to the bottom of `tests/unit/test_domains.py`:

```python
# ---------------------------------------------------------------------------
# Enrichment helper tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDomainListEnrichment:
    def test_last_scan_attached(self, domain, completed_session):
        from apps.core.domains.models import Domain
        from apps.core.domains.views import _enrich_domains
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        assert domains[0].last_scan == completed_session

    def test_never_scanned_domain_has_no_last_scan(self, domain):
        from apps.core.domains.models import Domain
        from apps.core.domains.views import _enrich_domains
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        assert domains[0].last_scan is None

    def test_last_scan_shows_any_status(self, domain):
        from apps.core.domains.models import Domain
        from apps.core.domains.views import _enrich_domains
        from apps.core.scans.models import ScanSession
        running = ScanSession.objects.create(domain="example.com", status="running")
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        assert domains[0].last_scan == running

    def test_findings_summary_counts(self, domain, completed_session):
        from apps.core.domains.models import Domain
        from apps.core.domains.views import _enrich_domains
        from apps.core.findings.models import Finding
        Finding.objects.create(
            session=completed_session, source="web_checker", target="example.com",
            check_type="missing_header", severity="critical", status="open",
            title="X", description="X", remediation="X",
        )
        Finding.objects.create(
            session=completed_session, source="web_checker", target="example.com",
            check_type="missing_header", severity="critical", status="open",
            title="X", description="X", remediation="X",
        )
        Finding.objects.create(
            session=completed_session, source="web_checker", target="example.com",
            check_type="cors", severity="high", status="open",
            title="X", description="X", remediation="X",
        )
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        fs = domains[0].findings_summary
        assert fs.get("critical") == 2
        assert fs.get("high") == 1

    def test_findings_excludes_resolved(self, domain, completed_session):
        from apps.core.domains.models import Domain
        from apps.core.domains.views import _enrich_domains
        from apps.core.findings.models import Finding
        Finding.objects.create(
            session=completed_session, source="web_checker", target="example.com",
            check_type="missing_header", severity="critical", status="resolved",
            title="X", description="X", remediation="X",
        )
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        assert domains[0].findings_summary == {}

    def test_findings_excludes_info(self, domain, completed_session):
        from apps.core.domains.models import Domain
        from apps.core.domains.views import _enrich_domains
        from apps.core.findings.models import Finding
        Finding.objects.create(
            session=completed_session, source="web_checker", target="example.com",
            check_type="banner", severity="info", status="open",
            title="X", description="X", remediation="X",
        )
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        assert "info" not in domains[0].findings_summary

    def test_findings_empty_when_no_completed_scan(self, domain):
        from apps.core.domains.models import Domain
        from apps.core.domains.views import _enrich_domains
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        running = ScanSession.objects.create(domain="example.com", status="running")
        Finding.objects.create(
            session=running, source="web_checker", target="example.com",
            check_type="cors", severity="high", status="open",
            title="X", description="X", remediation="X",
        )
        domains = list(Domain.objects.all())
        _enrich_domains(domains)
        assert domains[0].findings_summary == {}

    def test_enrich_empty_list(self):
        # Should not raise — no queries needed for empty list
        from apps.core.domains.views import _enrich_domains
        _enrich_domains([])  # must not raise
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
uv run pytest tests/unit/test_domains.py::TestDomainListEnrichment -v
```

Expected: `ImportError` or `AttributeError` — `_enrich_domains` does not exist yet.

- [ ] **Step 3: Implement `_enrich_domains` and wire it into the view**

Replace the imports block and add the helper in `apps/core/domains/views.py`. The final file should look like:

```python
import logging

from django.contrib import messages
from django.db import transaction
from django.db.models import Count
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required

logger = logging.getLogger(__name__)

from apps.core.scans.models import ScanSession
from apps.core.insights.models import ScanSummary
from apps.core.queries import latest_session_ids
from apps.core.findings.models import Finding
from .models import Domain
from .forms import DomainForm


def _enrich_domains(domains):
    """Attach last_scan and findings_summary to each Domain object in-place."""
    domain_names = [d.name for d in domains]
    if not domain_names:
        return

    # Latest session per domain (any status) — for Last Scan column
    latest_sessions = {}
    for session in ScanSession.objects.filter(
        domain__in=domain_names
    ).order_by("domain", "-start_time"):
        if session.domain not in latest_sessions:
            latest_sessions[session.domain] = session

    # Open findings from latest completed session — for Findings column
    latest_ids = latest_session_ids(domains=domain_names)
    findings_by_domain = {}
    if latest_ids:
        for row in (
            Finding.objects
            .filter(session_id__in=latest_ids, status="open")
            .exclude(severity="info")
            .values("session__domain", "severity")
            .annotate(count=Count("id"))
        ):
            d = row["session__domain"]
            findings_by_domain.setdefault(d, {})[row["severity"]] = row["count"]

    for domain in domains:
        domain.last_scan = latest_sessions.get(domain.name)
        domain.findings_summary = findings_by_domain.get(domain.name, {})


@login_required
def domain_list(request):
    if request.method == "POST":
        form = DomainForm(request.POST)
        if form.is_valid():
            domain = form.save()
            messages.success(request, f"Domain {domain.name} added successfully.")
            return redirect("domain-list")
    else:
        form = DomainForm()

    domains = list(Domain.objects.all())
    _enrich_domains(domains)

    recurring_domains = set()
    try:
        from apps.core.scheduler import get_scheduler
        for job in get_scheduler().get_jobs():
            if job.id.startswith("recurring_"):
                recurring_domains.add(job.id[len("recurring_"):])
    except Exception:
        logger.exception("[domain_list] Failed to fetch recurring scheduled jobs")

    return render(request, "domains/list.html", {
        "domains": domains,
        "form": form,
        "recurring_domains": recurring_domains,
    })


@login_required
def domain_toggle(request, pk):
    domain = get_object_or_404(Domain, pk=pk)
    domain.is_active = not domain.is_active
    domain.save()
    status = "activated" if domain.is_active else "paused"
    messages.success(request, f"Domain {domain.name} {status}.")
    return redirect("domain-list")


@login_required
def domain_delete(request, pk):
    domain = get_object_or_404(Domain, pk=pk)
    if request.method == "POST":
        domain_name = domain.name
        with transaction.atomic():
            active = ScanSession.objects.filter(
                domain=domain_name, status__in=["pending", "running"]
            ).exists()
            if active:
                domains = list(Domain.objects.all())
                _enrich_domains(domains)
                form = DomainForm()
                return render(request, "domains/list.html", {
                    "domains": domains,
                    "form": form,
                    "delete_error": f"Cannot delete '{domain_name}' — a scan is currently active. Wait for it to finish.",
                })
            ScanSession.objects.filter(domain=domain_name).delete()
            ScanSummary.objects.filter(domain=domain_name).delete()
            domain.delete()
            from apps.core.insights.builder import _rebuild_finding_type_summaries
            _rebuild_finding_type_summaries()
            messages.success(request, f"Domain {domain_name} and all its scan data deleted.")
    return redirect("domain-list")
```

Note: `Domain.objects.all()` changed to `list(Domain.objects.all())` in `domain_list` so the queryset is evaluated before `_enrich_domains` iterates it.

- [ ] **Step 4: Run tests to confirm they pass**

```bash
uv run pytest tests/unit/test_domains.py::TestDomainListEnrichment -v
```

Expected: all 8 tests PASS.

- [ ] **Step 5: Run the full test suite to check nothing broke**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/core/domains/views.py tests/unit/test_domains.py
git commit -m "feat: add domain enrichment helper for last scan and findings summary"
```

---

## Task 2: Template columns

**Files:**
- Modify: `templates/domains/list.html`
- Test: `tests/unit/test_domains.py` (new tests in `TestDomainListEnrichment`)

- [ ] **Step 1: Write failing rendering tests**

Add these tests to the `TestDomainListEnrichment` class in `tests/unit/test_domains.py` (after the existing tests):

```python
    def test_last_scan_date_rendered(self, auth_client, domain, completed_session):
        resp = auth_client.get(reverse("domain-list"))
        assert resp.status_code == 200
        # Status sub-text rendered
        assert b"completed" in resp.content

    def test_never_scanned_text_rendered(self, auth_client, domain):
        resp = auth_client.get(reverse("domain-list"))
        assert resp.status_code == 200
        assert b"Never scanned" in resp.content

    def test_findings_badges_rendered(self, auth_client, domain, completed_session):
        from apps.core.findings.models import Finding
        Finding.objects.create(
            session=completed_session, source="web_checker", target="example.com",
            check_type="cors", severity="critical", status="open",
            title="X", description="X", remediation="X",
        )
        resp = auth_client.get(reverse("domain-list"))
        assert b"critical" in resp.content

    def test_findings_column_shows_dash_when_clean(self, auth_client, domain, completed_session):
        # Clean domain (no open findings) shows em dash
        resp = auth_client.get(reverse("domain-list"))
        assert "—".encode("utf-8") in resp.content

    def test_confirm_delete_colspan_is_6(self, auth_client, domain):
        resp = auth_client.get(reverse("domain-list"))
        assert b'colspan="6"' in resp.content
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
uv run pytest tests/unit/test_domains.py::TestDomainListEnrichment::test_last_scan_date_rendered tests/unit/test_domains.py::TestDomainListEnrichment::test_never_scanned_text_rendered tests/unit/test_domains.py::TestDomainListEnrichment::test_findings_badges_rendered tests/unit/test_domains.py::TestDomainListEnrichment::test_findings_column_shows_dash_when_clean tests/unit/test_domains.py::TestDomainListEnrichment::test_confirm_delete_colspan_is_6 -v
```

Expected: FAIL — "Never scanned" not in content, colspan is 5, no findings column yet.

- [ ] **Step 3: Update the template**

Replace `templates/domains/list.html` with:

```html
{% extends "base.html" %}

{% block title %}Domains{% endblock %}

{% block content %}
<div class="mb-8">
  <h1 class="text-2xl font-bold text-gray-900">Domains</h1>
  <p class="text-gray-500 text-sm mt-1">Apex domains registered for continuous monitoring</p>
</div>

{% if delete_error %}
<div class="mb-4 px-4 py-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
  {{ delete_error }}
</div>
{% endif %}

<!-- Add Domain Form -->
<div class="bg-white rounded-lg shadow mb-6">
  <div class="px-6 py-4 border-b border-gray-200">
    <h2 class="font-semibold text-gray-700">Add Domain</h2>
  </div>
  <form method="post" class="px-6 py-4">
    {% csrf_token %}
    <div class="flex flex-col sm:flex-row gap-3 items-start">
      <div class="flex-1">
        {{ form.name }}
        {% if form.name.errors %}
        <p class="text-red-500 text-xs mt-1">{{ form.name.errors.0 }}</p>
        {% endif %}
      </div>
      <div class="flex items-center gap-2 pt-2 sm:pt-0 shrink-0">
        {{ form.is_primary }}
        <label class="text-sm text-gray-600">Primary</label>
      </div>
      <div class="shrink-0">
        <button type="submit" class="w-full sm:w-auto bg-indigo-600 text-white px-5 py-2 rounded-md text-sm font-medium hover:bg-indigo-700">
          Add Domain
        </button>
      </div>
    </div>
  </form>
</div>

<!-- Domain List -->
<div class="bg-white rounded-lg shadow">
  <div class="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
    <h2 class="font-semibold text-gray-700">Registered Domains</h2>
    <span class="text-xs text-gray-400">{{ domains|length }} domain{{ domains|length|pluralize }}</span>
  </div>

  {% if domains %}
  <table class="min-w-full divide-y divide-gray-100">
    <thead class="bg-gray-50">
      <tr>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Domain</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Last Scan</th>
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Findings</th>
        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Actions</th>
      </tr>
    </thead>
    <tbody class="divide-y divide-gray-100">
      {% for domain in domains %}
      <tbody x-data="{ confirmDelete: false }">
      <tr class="hover:bg-gray-50">
        <td class="px-6 py-4 text-sm font-mono font-medium text-gray-900">
          {{ domain.name }}
          {% if domain.name in recurring_domains %}
          <span class="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-violet-100 text-violet-700">scheduled</span>
          {% endif %}
        </td>
        <td class="px-6 py-4 text-sm">
          {% if domain.is_primary %}
          <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-indigo-100 text-indigo-700">Primary</span>
          {% else %}
          <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-500">Related</span>
          {% endif %}
        </td>
        <td class="px-6 py-4 text-sm">
          {% if domain.is_active %}
          <span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-700">
            <span class="w-1.5 h-1.5 bg-green-500 rounded-full"></span> Active
          </span>
          {% else %}
          <span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-500">
            <span class="w-1.5 h-1.5 bg-gray-400 rounded-full"></span> Paused
          </span>
          {% endif %}
        </td>
        <td class="px-6 py-4 text-sm">
          {% if domain.last_scan %}
          <div class="text-gray-500">{{ domain.last_scan.start_time|date:"M d, Y H:i" }}</div>
          <div class="text-xs text-slate-400">{{ domain.last_scan.status }}</div>
          {% else %}
          <span class="text-gray-400 italic">Never scanned</span>
          {% endif %}
        </td>
        <td class="px-6 py-4 text-sm">
          {% with fs=domain.findings_summary %}
          {% if fs %}
          <div class="flex flex-wrap gap-1">
            {% if fs.critical %}<span class="bg-red-50 text-red-600 text-xs font-semibold px-1.5 py-0.5 rounded">{{ fs.critical }} critical</span>{% endif %}
            {% if fs.high %}<span class="bg-orange-50 text-orange-600 text-xs font-semibold px-1.5 py-0.5 rounded">{{ fs.high }} high</span>{% endif %}
            {% if fs.medium %}<span class="bg-yellow-50 text-yellow-700 text-xs font-semibold px-1.5 py-0.5 rounded">{{ fs.medium }} medium</span>{% endif %}
            {% if fs.low %}<span class="bg-slate-100 text-slate-600 text-xs font-semibold px-1.5 py-0.5 rounded">{{ fs.low }} low</span>{% endif %}
          </div>
          {% else %}
          <span class="text-gray-400">—</span>
          {% endif %}
          {% endwith %}
        </td>
        <td class="px-6 py-4 text-right">
          <div class="flex items-center justify-end gap-3">
            <a href="{% url 'scan-start' %}?domain={{ domain.name }}" class="text-indigo-600 hover:underline text-sm">Scan</a>
            <form method="post" action="{% url 'domain-toggle' domain.pk %}" class="inline">
              {% csrf_token %}
              <button type="submit" class="text-gray-500 hover:text-gray-700 text-sm">
                {% if domain.is_active %}Pause{% else %}Resume{% endif %}
              </button>
            </form>
            <button @click="confirmDelete = true" x-show="!confirmDelete" class="text-red-500 hover:text-red-700 text-sm">Delete</button>
          </div>
        </td>
      </tr>
      <tr x-show="confirmDelete" x-cloak class="bg-red-50">
        <td colspan="6" class="px-6 py-3">
          <div class="flex items-center justify-between">
            <p class="text-sm text-red-700">
              Delete <span class="font-mono font-semibold">{{ domain.name }}</span>?
              This will remove all scan history and findings for this domain.
            </p>
            <div class="flex items-center gap-3 shrink-0 ml-6">
              <button @click="confirmDelete = false" class="text-sm text-gray-500 hover:text-gray-700">Cancel</button>
              <form method="post" action="{% url 'domain-delete' domain.pk %}" class="inline">
                {% csrf_token %}
                <button type="submit" class="bg-red-600 text-white text-sm px-4 py-1.5 rounded hover:bg-red-700">Yes, delete</button>
              </form>
            </div>
          </div>
        </td>
      </tr>
      </tbody>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="px-6 py-12 text-center text-gray-400">
    <p class="text-lg">No domains registered yet.</p>
    <p class="text-sm mt-1">Add your first apex domain above to start monitoring.</p>
  </div>
  {% endif %}
</div>
{% endblock %}
```

- [ ] **Step 4: Run the new rendering tests**

```bash
uv run pytest tests/unit/test_domains.py::TestDomainListEnrichment -v
```

Expected: all 13 tests PASS.

- [ ] **Step 5: Run the full test suite**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add templates/domains/list.html tests/unit/test_domains.py
git commit -m "feat: add Last Scan and Findings columns to domains table"
```
