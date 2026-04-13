# Insights Layout Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reorganize the insights page into a top-to-bottom narrative with 4 labeled sections (Security Posture → Remediation Progress → Where to Focus → Asset Coverage) and a KPI card row at the top.

**Architecture:** Two changes: (1) the insights view gains four KPI context variables from two new DB queries; (2) `templates/insights.html` is rewritten to use those variables and present all existing data in the new section order. No new models or URLs.

**Tech Stack:** Django views, Django templates, Tailwind CSS (CDN), Chart.js (CDN, page-scoped).

**Spec:** `docs/superpowers/specs/2026-04-13-insights-layout-redesign.md`

---

## File Map

| File | Change |
|---|---|
| `apps/core/insights/views.py` | Add `kpi_open_critical`, `kpi_open_high`, `kpi_new`, `kpi_fixed` to context |
| `templates/insights.html` | Full rewrite — 4 labeled sections + KPI row |
| `tests/unit/test_insights.py` | Add `TestInsightsKPIContext` (4 tests) + 2 integration tests in `TestInsightsView` |

---

## Task 1: KPI Context Variables

**Files:**
- Modify: `apps/core/insights/views.py`
- Test: `tests/unit/test_insights.py`

- [ ] **Step 1: Write the failing tests**

Add a new class at the end of `tests/unit/test_insights.py`:

```python
@pytest.mark.django_db
class TestInsightsKPIContext:
    def _get_context(self, auth_client):
        from django.test import RequestFactory
        from django.contrib.auth.models import User
        from apps.core.insights.views import insights
        factory = RequestFactory()
        req = factory.get("/insights/")
        req.user = User.objects.get(username="testuser")
        resp = insights(req)
        # insights() returns a TemplateResponse — resolve context
        resp.render()
        return resp.context_data

    def test_kpi_open_critical_counts_open_critical_only(self, auth_client, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        session = ScanSession.objects.create(domain="example.com", scan_type="full")
        Finding.objects.create(session=session, source="nmap", target="1.2.3.4",
                               check_type="cve", severity="critical", title="CVE-A", status="open")
        Finding.objects.create(session=session, source="nmap", target="1.2.3.4",
                               check_type="cve", severity="critical", title="CVE-B", status="resolved")
        ctx = self._get_context(auth_client)
        assert ctx["kpi_open_critical"] == 1

    def test_kpi_open_high_counts_open_high_only(self, auth_client, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        session = ScanSession.objects.create(domain="example.com", scan_type="full")
        Finding.objects.create(session=session, source="nmap", target="1.2.3.4",
                               check_type="cve", severity="high", title="High-A", status="open")
        Finding.objects.create(session=session, source="nmap", target="1.2.3.4",
                               check_type="cve", severity="high", title="High-B", status="acknowledged")
        ctx = self._get_context(auth_client)
        assert ctx["kpi_open_high"] == 1

    def test_kpi_new_and_fixed_from_latest_summary(self, auth_client, db, domain, scan_summary):
        # scan_summary fixture: new_exposures=3, removed_exposures=0
        ctx = self._get_context(auth_client)
        assert ctx["kpi_new"] == 3
        assert ctx["kpi_fixed"] == 0

    def test_kpi_zero_when_no_scans(self, auth_client, db):
        ctx = self._get_context(auth_client)
        assert ctx["kpi_open_critical"] == 0
        assert ctx["kpi_open_high"] == 0
        assert ctx["kpi_new"] == 0
        assert ctx["kpi_fixed"] == 0
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/unit/test_insights.py::TestInsightsKPIContext -v
```

Expected: `KeyError` on `kpi_open_critical` — context key does not exist yet.

- [ ] **Step 3: Add KPI variables to the view**

In `apps/core/insights/views.py`, add two new queries after the `summaries` list is built (after line `summaries = list(summaries)`):

```python
    # ----- KPI counts -----
    kpi_open_critical = Finding.objects.filter(severity="critical", status="open").count()
    kpi_open_high = Finding.objects.filter(severity="high", status="open").count()
    kpi_new = summaries[-1].new_exposures if summaries else 0
    kpi_fixed = summaries[-1].removed_exposures if summaries else 0
```

Then add them to the `render()` call at the bottom (add after `"chart_data": chart_data`):

```python
        "kpi_open_critical": kpi_open_critical,
        "kpi_open_high": kpi_open_high,
        "kpi_new": kpi_new,
        "kpi_fixed": kpi_fixed,
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
uv run pytest tests/unit/test_insights.py::TestInsightsKPIContext -v
```

Expected: 4 PASSED.

- [ ] **Step 5: Commit**

```bash
git add apps/core/insights/views.py tests/unit/test_insights.py
git commit -m "feat(insights): add KPI context variables to insights view"
```

---

## Task 2: Restructure insights.html

**Files:**
- Modify: `templates/insights.html`
- Test: `tests/unit/test_insights.py` (add 2 tests to `TestInsightsView`)

- [ ] **Step 1: Write the failing integration tests**

Add two methods to `TestInsightsView` in `tests/unit/test_insights.py`:

```python
    def test_insights_shows_section_headers(self, auth_client, domain, scan_summary):
        resp = auth_client.get(reverse("insights"))
        assert b"Security Posture" in resp.content
        assert b"Remediation Progress" in resp.content
        assert b"Where to Focus" in resp.content
        assert b"Asset Coverage" in resp.content

    def test_insights_shows_kpi_cards(self, auth_client, domain, scan_summary):
        resp = auth_client.get(reverse("insights"))
        assert b"Open Critical" in resp.content
        assert b"Open High" in resp.content
        assert b"New This Scan" in resp.content
        assert b"Fixed This Scan" in resp.content
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
uv run pytest tests/unit/test_insights.py::TestInsightsView::test_insights_shows_section_headers tests/unit/test_insights.py::TestInsightsView::test_insights_shows_kpi_cards -v
```

Expected: both FAIL — old template has no section headers or KPI cards.

- [ ] **Step 3: Replace `templates/insights.html` entirely**

```html
{% extends "base.html" %}

{% block title %}Insights{% endblock %}

{% block content %}
<div class="mb-6">
  <h1 class="text-2xl font-bold text-gray-900">Insights</h1>
  <p class="text-gray-500 text-sm mt-1">Trends, patterns, and historical analysis across all scans</p>
</div>

{% if not scan_trend %}
<div class="bg-white rounded-lg shadow px-6 py-16 text-center text-gray-400">
  <p class="text-lg font-medium">No completed scans yet.</p>
  <p class="text-sm mt-1">Run a scan to start seeing trends.</p>
  <a href="{% url 'scan-start' %}" class="mt-4 inline-block bg-indigo-600 text-white px-4 py-2 rounded-md text-sm hover:bg-indigo-700">Start a Scan</a>
</div>
{% else %}

<!-- KPI Cards -->
<div class="grid grid-cols-4 gap-4 mb-8">
  <div class="bg-white rounded-lg border border-red-200 px-5 py-4">
    <div class="text-xs font-semibold text-red-500 uppercase tracking-wide">Open Critical</div>
    <div class="text-3xl font-bold text-red-600 mt-1">{{ kpi_open_critical }}</div>
    <div class="text-xs text-gray-400 mt-1">active findings</div>
  </div>
  <div class="bg-white rounded-lg border border-orange-200 px-5 py-4">
    <div class="text-xs font-semibold text-orange-500 uppercase tracking-wide">Open High</div>
    <div class="text-3xl font-bold text-orange-600 mt-1">{{ kpi_open_high }}</div>
    <div class="text-xs text-gray-400 mt-1">active findings</div>
  </div>
  <div class="bg-white rounded-lg border border-green-200 px-5 py-4">
    <div class="text-xs font-semibold text-green-600 uppercase tracking-wide">New This Scan</div>
    <div class="text-3xl font-bold text-green-700 mt-1">+{{ kpi_new }}</div>
    <div class="text-xs text-gray-400 mt-1">new exposures</div>
  </div>
  <div class="bg-white rounded-lg border border-blue-200 px-5 py-4">
    <div class="text-xs font-semibold text-blue-600 uppercase tracking-wide">Fixed This Scan</div>
    <div class="text-3xl font-bold text-blue-700 mt-1">{{ kpi_fixed }}</div>
    <div class="text-xs text-gray-400 mt-1">exposures removed</div>
  </div>
</div>

<!-- Section 1: Security Posture -->
<div class="mb-8">
  <div class="flex items-center gap-2 mb-4">
    <div class="w-0.5 h-4 bg-indigo-500 rounded"></div>
    <h2 class="text-sm font-semibold text-slate-900">Security Posture</h2>
    <span class="text-xs text-slate-400">Finding severity across your last {{ scan_trend|length }} scans</span>
  </div>
  <div class="bg-white rounded-lg shadow">
    <div class="px-6 py-4 overflow-x-auto">
      <table class="min-w-full text-sm">
        <thead>
          <tr class="text-left text-xs text-gray-500 uppercase">
            <th class="pb-3 pr-6">Scan</th>
            <th class="pb-3 pr-6 text-red-500">Critical</th>
            <th class="pb-3 pr-6 text-orange-500">High</th>
            <th class="pb-3 pr-6 text-yellow-600">Medium</th>
            <th class="pb-3 pr-6 text-blue-500">Low</th>
            <th class="pb-3 w-full">Distribution</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100">
          {% for row in scan_trend %}
          <tr>
            <td class="py-2 pr-6 text-gray-700 whitespace-nowrap text-xs">{{ row.label }}</td>
            <td class="py-2 pr-6 font-semibold {% if row.critical > 0 %}text-red-600{% else %}text-gray-300{% endif %}">{{ row.critical }}</td>
            <td class="py-2 pr-6 font-semibold {% if row.high > 0 %}text-orange-500{% else %}text-gray-300{% endif %}">{{ row.high }}</td>
            <td class="py-2 pr-6 font-semibold {% if row.medium > 0 %}text-yellow-600{% else %}text-gray-300{% endif %}">{{ row.medium }}</td>
            <td class="py-2 pr-6 font-semibold {% if row.low > 0 %}text-blue-500{% else %}text-gray-300{% endif %}">{{ row.low }}</td>
            <td class="py-2">
              <div class="flex gap-1 items-center">
                {% if row.critical > 0 %}<div class="h-4 bg-red-500 rounded" style="width: {{ row.critical }}rem; max-width: 8rem;" title="{{ row.critical }} critical"></div>{% endif %}
                {% if row.high > 0 %}<div class="h-4 bg-orange-400 rounded" style="width: {{ row.high }}rem; max-width: 8rem;" title="{{ row.high }} high"></div>{% endif %}
                {% if row.medium > 0 %}<div class="h-4 bg-yellow-400 rounded" style="width: {{ row.medium }}rem; max-width: 8rem;" title="{{ row.medium }} medium"></div>{% endif %}
                {% if row.low > 0 %}<div class="h-4 bg-blue-300 rounded" style="width: {{ row.low }}rem; max-width: 8rem;" title="{{ row.low }} low"></div>{% endif %}
                {% if row.critical == 0 and row.high == 0 and row.medium == 0 and row.low == 0 %}
                <span class="text-xs text-gray-300">No findings</span>
                {% endif %}
              </div>
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      <div class="flex gap-4 mt-3 text-xs text-gray-400">
        <span class="flex items-center gap-1"><span class="inline-block w-3 h-3 bg-red-500 rounded"></span> Critical</span>
        <span class="flex items-center gap-1"><span class="inline-block w-3 h-3 bg-orange-400 rounded"></span> High</span>
        <span class="flex items-center gap-1"><span class="inline-block w-3 h-3 bg-yellow-400 rounded"></span> Medium</span>
        <span class="flex items-center gap-1"><span class="inline-block w-3 h-3 bg-blue-300 rounded"></span> Low</span>
      </div>
    </div>
  </div>
</div>

<!-- Section 2: Remediation Progress -->
<div class="mb-8">
  <div class="flex items-center gap-2 mb-4">
    <div class="w-0.5 h-4 bg-green-500 rounded"></div>
    <h2 class="text-sm font-semibold text-slate-900">Remediation Progress</h2>
    <span class="text-xs text-slate-400">New exposures introduced vs. findings fixed per scan</span>
  </div>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <div class="bg-white rounded-lg shadow">
      <div class="px-6 py-4 border-b border-gray-200">
        <h3 class="text-sm font-semibold text-gray-700">New vs Fixed per Scan</h3>
      </div>
      <div class="px-6 py-4">
        {% if delta_trend %}
        <table class="min-w-full text-sm">
          <thead>
            <tr class="text-left text-xs text-gray-500 uppercase">
              <th class="pb-3 pr-4">Scan</th>
              <th class="pb-3 pr-4">New</th>
              <th class="pb-3">Fixed</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100">
            {% for row in delta_trend %}
            <tr>
              <td class="py-2 pr-4 text-gray-600 whitespace-nowrap text-xs">{{ row.label }}</td>
              <td class="py-2 pr-4 font-semibold {% if row.new > 0 %}text-red-600{% else %}text-gray-300{% endif %}">+{{ row.new }}</td>
              <td class="py-2 font-semibold {% if row.removed > 0 %}text-green-600{% else %}text-gray-300{% endif %}">-{{ row.removed }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
        {% else %}
        <p class="text-gray-400 text-sm">No delta data yet. Requires at least 2 scans per domain.</p>
        {% endif %}
      </div>
    </div>
    <div class="bg-white rounded-lg shadow">
      <div class="px-6 py-4 border-b border-gray-200">
        <h3 class="text-sm font-semibold text-gray-700">Recurring Finding Types</h3>
      </div>
      <div class="px-6 py-4">
        {% if top_finding_types %}
        <ul class="divide-y divide-gray-100">
          {% for f in top_finding_types %}
          <li class="py-2 flex items-center justify-between text-sm gap-3">
            <div class="min-w-0">
              <p class="text-gray-800 truncate">{{ f.title }}</p>
              <p class="text-xs text-gray-400 mt-0.5 uppercase">{{ f.check_type }}</p>
            </div>
            <div class="flex items-center gap-2 shrink-0">
              {% include "partials/severity_badge.html" with severity=f.severity %}
              <span class="text-xs text-gray-500 w-8 text-right">×{{ f.occurrence_count }}</span>
            </div>
          </li>
          {% endfor %}
        </ul>
        {% else %}
        <p class="text-gray-400 text-sm">No findings recorded yet.</p>
        {% endif %}
      </div>
    </div>
  </div>
</div>

<!-- Section 3: Where to Focus -->
<div class="mb-8">
  <div class="flex items-center gap-2 mb-4">
    <div class="w-0.5 h-4 bg-orange-500 rounded"></div>
    <h2 class="text-sm font-semibold text-slate-900">Where to Focus</h2>
    <span class="text-xs text-slate-400">Top vulnerable domains and services from latest scans</span>
  </div>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <div class="bg-white rounded-lg shadow">
      <div class="px-6 py-4 border-b border-gray-200">
        <h3 class="text-sm font-semibold text-gray-700">Top Vulnerable Domains</h3>
      </div>
      <div class="px-6 py-4">
        {% if top_hosts %}
        <ul class="divide-y divide-gray-100">
          {% for host in top_hosts %}
          <li class="py-3 flex items-center justify-between text-sm">
            <span class="text-gray-800 font-mono">{{ host.domain }}</span>
            <div class="flex items-center gap-4">
              <div class="w-48 bg-gray-100 rounded-full h-2">
                <div class="bg-indigo-500 h-2 rounded-full" style="width: {% widthratio host.count top_hosts.0.count 100 %}%"></div>
              </div>
              <span class="text-xs text-gray-500 w-24 text-right">{{ host.count }} finding{{ host.count|pluralize }}</span>
            </div>
          </li>
          {% endfor %}
        </ul>
        {% else %}
        <p class="text-gray-400 text-sm">No findings recorded yet.</p>
        {% endif %}
      </div>
    </div>
    {% if top_services %}
    <div class="bg-white rounded-lg shadow">
      <div class="px-6 py-4 border-b border-gray-200">
        <h3 class="text-sm font-semibold text-gray-700">Top Vulnerable Services</h3>
      </div>
      <table class="min-w-full divide-y divide-gray-100">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Service</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Version</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">CVEs</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Max CVSS</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100">
          {% for s in top_services %}
          <tr class="hover:bg-gray-50">
            <td class="px-6 py-3 text-sm font-mono text-gray-900">{{ s.service|default:"unknown" }}</td>
            <td class="px-6 py-3 text-sm text-gray-600">{{ s.version|default:"-" }}</td>
            <td class="px-6 py-3 text-sm">
              <span class="px-2 py-0.5 rounded text-xs font-semibold bg-red-100 text-red-700">{{ s.cve_count }}</span>
            </td>
            <td class="px-6 py-3 text-sm font-semibold {% if s.max_cvss >= 7 %}text-red-600{% elif s.max_cvss >= 4 %}text-orange-500{% else %}text-gray-600{% endif %}">
              {{ s.max_cvss|default:"-" }}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% else %}
    <div class="bg-white rounded-lg shadow">
      <div class="px-6 py-4 border-b border-gray-200">
        <h3 class="text-sm font-semibold text-gray-700">Top Vulnerable Services</h3>
      </div>
      <div class="px-6 py-4">
        <p class="text-gray-400 text-sm">No CVE data yet. Requires an nmap scan.</p>
      </div>
    </div>
    {% endif %}
  </div>
</div>

<!-- Section 4: Asset Coverage -->
<div class="mb-8">
  <div class="flex items-center gap-2 mb-4">
    <div class="w-0.5 h-4 bg-slate-500 rounded"></div>
    <h2 class="text-sm font-semibold text-slate-900">Asset Coverage</h2>
    <span class="text-xs text-slate-400">Growth of discovered subdomains, IPs, ports, and URLs over time</span>
  </div>
  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <div class="bg-white rounded-lg shadow lg:col-span-2">
      <div class="px-6 py-4 border-b border-gray-200">
        <h3 class="text-sm font-semibold text-gray-700">Asset Growth Trend</h3>
      </div>
      <div class="px-6 py-4">
        <div style="position: relative; height: 280px; width: 100%;">
          <canvas id="assetGrowthChart"></canvas>
        </div>
      </div>
    </div>
    <div class="flex flex-col gap-6">
      {% with latest=scan_trend|last %}
      {% if latest.tool_breakdown %}
      <div class="bg-white rounded-lg shadow">
        <div class="px-6 py-4 border-b border-gray-200">
          <h3 class="text-sm font-semibold text-gray-700">Findings by Tool</h3>
          <p class="text-xs text-gray-400 mt-0.5">{{ latest.label }} · {{ latest.total }} findings</p>
        </div>
        <div class="px-6 py-4">
          <div class="grid grid-cols-2 gap-2">
            {% for tool, count in latest.tool_breakdown.items %}
            <div class="bg-gray-50 rounded px-3 py-2 border border-gray-100">
              <div class="text-xs text-gray-500 uppercase font-medium truncate">{{ tool }}</div>
              <div class="text-xl font-bold text-gray-900">{{ count }}</div>
            </div>
            {% endfor %}
          </div>
        </div>
      </div>
      {% endif %}
      {% endwith %}
      <div class="bg-white rounded-lg shadow">
        <div class="px-6 py-4 border-b border-gray-200">
          <h3 class="text-sm font-semibold text-gray-700">CVE Severity</h3>
        </div>
        <div class="px-6 py-4">
          {% if severity_distribution %}
          <div style="position: relative; height: 200px; width: 100%;">
            <canvas id="severityChart"></canvas>
          </div>
          {% else %}
          <p class="text-gray-400 text-sm text-center py-8">No CVEs detected yet.</p>
          {% endif %}
        </div>
      </div>
    </div>
  </div>
</div>

{% endif %}

{# Chart.js — loaded only on this page #}
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
{{ chart_data|json_script:"chart-data" }}
<script>
(function() {
  const data = JSON.parse(document.getElementById('chart-data').textContent);

  const growthCanvas = document.getElementById('assetGrowthChart');
  if (growthCanvas && data.asset_growth_labels.length > 0) {
    new Chart(growthCanvas, {
      type: 'line',
      data: {
        labels: data.asset_growth_labels,
        datasets: [
          { label: 'Active Subdomains', data: data.asset_growth_subdomains, borderColor: '#6366f1', backgroundColor: '#6366f120', tension: 0.3 },
          { label: 'Public IPs', data: data.asset_growth_ips, borderColor: '#10b981', backgroundColor: '#10b98120', tension: 0.3 },
          { label: 'Open Ports', data: data.asset_growth_ports, borderColor: '#f59e0b', backgroundColor: '#f59e0b20', tension: 0.3 },
          { label: 'Web URLs', data: data.asset_growth_urls, borderColor: '#3b82f6', backgroundColor: '#3b82f620', tension: 0.3 },
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 } } } },
        scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
      }
    });
  }

  const sevCanvas = document.getElementById('severityChart');
  if (sevCanvas) {
    const sev = data.severity_distribution || {};
    const labels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
    const values = [sev.critical || 0, sev.high || 0, sev.medium || 0, sev.low || 0, sev.info || 0];
    const total = values.reduce((a, b) => a + b, 0);
    if (total > 0) {
      new Chart(sevCanvas, {
        type: 'doughnut',
        data: {
          labels: labels,
          datasets: [{
            data: values,
            backgroundColor: ['#dc2626', '#ea580c', '#facc15', '#3b82f6', '#9ca3af'],
            borderWidth: 2,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 } } } }
        }
      });
    }
  }
})();
</script>
{% endblock %}
```

- [ ] **Step 4: Run the two new integration tests**

```bash
uv run pytest tests/unit/test_insights.py::TestInsightsView::test_insights_shows_section_headers tests/unit/test_insights.py::TestInsightsView::test_insights_shows_kpi_cards -v
```

Expected: 2 PASSED.

- [ ] **Step 5: Run full test suite**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all PASSED, no regressions.

- [ ] **Step 6: Commit**

```bash
git add templates/insights.html tests/unit/test_insights.py
git commit -m "feat(insights): restructure page into 4 labeled sections with KPI row"
```
