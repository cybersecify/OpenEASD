# Dashboard UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace 4 separate severity columns in the domain status table with inline badges + a Δ New column, and merge the two redundant urgent tables into one.

**Architecture:** Two template-only tasks plus a small view cleanup. Task 1 changes the domain status table (no view changes). Task 2 removes the urgent_cves context variable from the view and updates the urgent findings table.

**Tech Stack:** Django 5 templates, Tailwind CSS CDN, pytest-django

---

## File Map

| File | Change |
|---|---|
| `apps/core/dashboard/views.py` | Remove `urgent_cves` query + context var (Task 2) |
| `templates/dashboard.html` | Domain table: replace 4 severity cols with badges + Δ New (Task 1); remove CVE table, add Source col to urgent findings (Task 2) |
| `tests/unit/test_core.py` | New class `TestDashboardRedesign` — 7 tests across both tasks |

---

## Task 1: Domain table — inline badges + Δ New column

**Files:**
- Modify: `templates/dashboard.html`
- Test: `tests/unit/test_core.py`

- [ ] **Step 1: Write failing tests**

Add this class to `tests/unit/test_core.py` (after `TestDashboardQueryCorrectness`):

```python
# ---------------------------------------------------------------------------
# Dashboard redesign tests
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDashboardRedesign:
    def _make_domain_with_summary(self, db, name="example.com", critical=0, high=0,
                                   medium=0, low=0, new_exposures=0):
        from apps.core.domains.models import Domain
        from apps.core.scans.models import ScanSession
        from apps.core.insights.models import ScanSummary
        from django.utils import timezone
        Domain.objects.get_or_create(name=name, defaults={"is_primary": True, "is_active": True})
        session = ScanSession.objects.create(
            domain=name, scan_type="full", status="completed", end_time=timezone.now()
        )
        ScanSummary.objects.create(
            session=session, domain=name, scan_date=timezone.now(),
            critical_count=critical, high_count=high, medium_count=medium,
            low_count=low, total_findings=critical + high + medium + low,
            new_exposures=new_exposures, removed_exposures=0,
        )
        return session

    def test_delta_new_shown_when_positive(self, auth_client, db):
        self._make_domain_with_summary(db, new_exposures=3)
        resp = auth_client.get("/")
        assert resp.status_code == 200
        assert b"+3" in resp.content

    def test_delta_new_not_shown_when_zero(self, auth_client, db):
        self._make_domain_with_summary(db, new_exposures=0)
        resp = auth_client.get("/")
        assert b"+0" not in resp.content

    def test_domain_table_no_separate_crit_column(self, auth_client, db):
        self._make_domain_with_summary(db)
        resp = auth_client.get("/")
        # Old separate "Crit" <th> must be gone
        assert b">Crit<" not in resp.content

    def test_inline_badges_shown_for_domain_with_findings(self, auth_client, db):
        self._make_domain_with_summary(db, critical=2, high=5)
        resp = auth_client.get("/")
        assert b"2 crit" in resp.content
        assert b"5 high" in resp.content
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
uv run pytest tests/unit/test_core.py::TestDashboardRedesign -v
```

Expected: `FAIL` — `+3` not in content, `Crit` still in content, badges not rendered.

- [ ] **Step 3: Update the domain status table `<thead>`**

In `templates/dashboard.html`, find the `<thead>` block of the Domain Status table (the one with `Crit`, `High`, `Med`, `Low` headers). Replace those 4 `<th>` elements with 2:

**Find (the 4 severity headers):**
```html
        <th class="px-6 py-3 text-center text-xs font-medium text-red-500 uppercase">Crit</th>
        <th class="px-6 py-3 text-center text-xs font-medium text-orange-500 uppercase">High</th>
        <th class="px-6 py-3 text-center text-xs font-medium text-yellow-600 uppercase">Med</th>
        <th class="px-6 py-3 text-center text-xs font-medium text-blue-500 uppercase">Low</th>
```

**Replace with:**
```html
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Findings</th>
        <th class="px-6 py-3 text-center text-xs font-medium text-yellow-600 uppercase">&#916; New</th>
```

- [ ] **Step 4: Update the domain status table `<tbody>` row**

Find the 4 severity `<td>` cells in the `{% for item in domain_status %}` row. They start with:
```html
        <td class="px-6 py-3 text-center text-sm font-semibold {% if item.summary.critical_count > 0 %}text-red-600
```

Replace all 4 `<td>` cells (critical, high, medium, low) with these 2 cells:

```html
        <td class="px-6 py-4 text-sm">
          {% if item.summary %}
          <div class="flex flex-wrap gap-1">
            {% if item.summary.critical_count %}
            <a href="{% url 'finding-list' %}?session_id={{ item.latest_session.id }}&severity=critical"
               class="bg-red-50 text-red-600 text-xs font-semibold px-1.5 py-0.5 rounded hover:underline">{{ item.summary.critical_count }} crit</a>
            {% endif %}
            {% if item.summary.high_count %}
            <a href="{% url 'finding-list' %}?session_id={{ item.latest_session.id }}&severity=high"
               class="bg-orange-50 text-orange-600 text-xs font-semibold px-1.5 py-0.5 rounded hover:underline">{{ item.summary.high_count }} high</a>
            {% endif %}
            {% if item.summary.medium_count %}
            <a href="{% url 'finding-list' %}?session_id={{ item.latest_session.id }}&severity=medium"
               class="bg-yellow-50 text-yellow-700 text-xs font-semibold px-1.5 py-0.5 rounded hover:underline">{{ item.summary.medium_count }} med</a>
            {% endif %}
            {% if item.summary.low_count %}
            <a href="{% url 'finding-list' %}?session_id={{ item.latest_session.id }}&severity=low"
               class="bg-slate-100 text-slate-600 text-xs font-semibold px-1.5 py-0.5 rounded hover:underline">{{ item.summary.low_count }} low</a>
            {% endif %}
          </div>
          {% else %}
          <span class="text-gray-300">—</span>
          {% endif %}
        </td>
        <td class="px-6 py-4 text-center">
          {% if item.summary.new_exposures %}
          <span class="bg-yellow-100 text-yellow-800 text-xs font-semibold px-2 py-0.5 rounded-full">+{{ item.summary.new_exposures }}</span>
          {% else %}
          <span class="text-gray-300 text-sm">—</span>
          {% endif %}
        </td>
```

- [ ] **Step 5: Run tests to confirm they pass**

```bash
uv run pytest tests/unit/test_core.py::TestDashboardRedesign -v
```

Expected: all 4 tests PASS.

- [ ] **Step 6: Run full suite**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests PASS.

- [ ] **Step 7: Commit**

```bash
git add templates/dashboard.html tests/unit/test_core.py
git commit -m "feat: replace severity columns with inline badges and delta new in domain status table"
```

---

## Task 2: Remove CVE table · add Source column to urgent findings

**Files:**
- Modify: `apps/core/dashboard/views.py`
- Modify: `templates/dashboard.html`
- Test: `tests/unit/test_core.py`

- [ ] **Step 1: Write failing tests**

Add these 3 tests to the `TestDashboardRedesign` class in `tests/unit/test_core.py`:

```python
    def test_urgent_cves_not_in_context(self, auth_client, db):
        resp = auth_client.get("/")
        assert "urgent_cves" not in resp.context

    def test_urgent_findings_shows_source_column(self, auth_client, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        from apps.core.domains.models import Domain
        from django.utils import timezone
        Domain.objects.get_or_create(name="example.com", defaults={"is_active": True})
        session = ScanSession.objects.create(
            domain="example.com", scan_type="full", status="completed",
            end_time=timezone.now()
        )
        Finding.objects.create(
            session=session, source="web_checker", target="example.com",
            check_type="missing_header", severity="high", title="Missing HSTS",
            description="X", remediation="X",
        )
        resp = auth_client.get("/")
        assert b"Source" in resp.content
        assert b"web_checker" in resp.content

    def test_urgent_findings_uses_session_domain(self, auth_client, db):
        from apps.core.scans.models import ScanSession
        from apps.core.findings.models import Finding
        from apps.core.domains.models import Domain
        from django.utils import timezone
        Domain.objects.get_or_create(name="example.com", defaults={"is_active": True})
        session = ScanSession.objects.create(
            domain="example.com", scan_type="full", status="completed",
            end_time=timezone.now()
        )
        # nmap finding — target is IP:port, but session.domain is "example.com"
        Finding.objects.create(
            session=session, source="nmap", target="1.2.3.4:443",
            check_type="cve", severity="critical", title="CVE-2023-1234",
            description="X", remediation="X",
            extra={"cve": "CVE-2023-1234", "cvss_score": 9.8},
        )
        resp = auth_client.get("/")
        # Must show apex domain, not raw IP:port
        assert b"example.com" in resp.content
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
uv run pytest tests/unit/test_core.py::TestDashboardRedesign::test_urgent_cves_not_in_context tests/unit/test_core.py::TestDashboardRedesign::test_urgent_findings_shows_source_column tests/unit/test_core.py::TestDashboardRedesign::test_urgent_findings_uses_session_domain -v
```

Expected: `FAIL` — `urgent_cves` still in context, "Source" not in response, domain column shows target not session domain.

- [ ] **Step 3: Remove urgent_cves from the view**

In `apps/core/dashboard/views.py`, find and remove the entire `urgent_cves` block (lines ~83–89):

```python
    # Also include high-severity nmap CVEs
    urgent_cves = list(
        Finding.objects.filter(
            session_id__in=latest_completed_ids,
            source="nmap",
            severity__in=["critical", "high"],
        ).select_related("session").order_by("-discovered_at")[:8]
    )
```

Also remove `"urgent_cves": urgent_cves,` from the `render()` call context dict.

The final `render()` call should be:

```python
    return render(request, "dashboard.html", {
        "domain_status": domain_status,
        "current_critical": current_critical,
        "current_high": current_high,
        "running_count": running_count,
        "active_domain_count": len(active_domains),
        "urgent_findings": urgent_findings,
        "asset_counts": asset_counts,
        "latest_scan_uuid": latest_completed_session.uuid if latest_completed_session else None,
    })
```

- [ ] **Step 4: Remove the CVE table block from the template**

In `templates/dashboard.html`, find and delete the entire Urgent CVEs section — it starts with:
```html
<!-- Urgent CVE Findings (from nmap NSE vulners) -->
{% if urgent_cves %}
```
and ends with:
```html
</div>
{% endif %}
```
(the closing `{% endif %}` of the `urgent_cves` block, around line 209). Delete the whole block.

- [ ] **Step 5: Update the urgent findings table**

In `templates/dashboard.html`, find the Urgent Findings `<thead>` row. Replace the `Type` `<th>` with `Source`:

**Find:**
```html
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
```

**Replace with:**
```html
        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
```

Then in the `{% for f in urgent_findings %}` row, update 2 cells:

**Find (domain cell):**
```html
        <td class="px-6 py-3 text-sm font-mono text-gray-600">{{ f.domain }}</td>
        <td class="px-6 py-3 text-xs text-gray-500 uppercase">{{ f.check_type }}</td>
```

**Replace with:**
```html
        <td class="px-6 py-3 text-sm font-mono text-gray-600">{{ f.session.domain }}</td>
        <td class="px-6 py-3 text-xs text-gray-500 uppercase">{{ f.source }}</td>
```

- [ ] **Step 6: Run tests to confirm they pass**

```bash
uv run pytest tests/unit/test_core.py::TestDashboardRedesign -v
```

Expected: all 7 tests PASS.

- [ ] **Step 7: Run full suite**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -v
```

Expected: all tests PASS.

- [ ] **Step 8: Commit**

```bash
git add apps/core/dashboard/views.py templates/dashboard.html tests/unit/test_core.py
git commit -m "feat: remove redundant CVE table, add Source column to urgent findings"
```
