# Dashboard UI Redesign

**Date:** 2026-04-13
**Status:** Approved
**Scope:** `apps/core/dashboard/views.py`, `templates/dashboard.html`

## Problem

The dashboard partially answers "what is my security posture?" but misses two things a security team needs daily:

1. **What changed?** — `ScanSummary.new_exposures` and `removed_exposures` are computed per scan but never shown.
2. **What needs attention now?** — Urgent findings are split across two redundant tables (CVEs table + findings table). nmap CVEs are already in `urgent_findings`; the separate CVE table just repeats them with different columns.

The domain status table also wastes space with 4 separate severity columns (Crit / High / Med / Low).

## Goal

Two changes only:

1. **Domain status table** — replace 4 severity columns with inline badges + a Δ New column (`summary.new_exposures`)
2. **Urgent section** — remove the standalone CVE table; update the Urgent Findings table to show a Source column so CVE findings remain identifiable

## Design

### Domain Status table — new column layout

`Domain | Last Scan | Findings | Δ New | Status | Action` (6 columns, was 8)

**Findings cell** — inline severity badges, non-zero only (same pattern as the domains page):
```
3 crit  5 high  2 med
```
Uses `summary.critical_count`, `summary.high_count`, `summary.medium_count`, `summary.low_count`. Links each badge to `?session_id=<latest_session.id>&severity=<severity>` (same as current per-severity links). Shows "—" if no summary.

**Δ New cell** — `summary.new_exposures` from the latest scan summary:
- If `> 0`: yellow pill `+N` (`bg-yellow-100 text-yellow-800`)
- If `0` or no summary: "—" in muted text

### Urgent Findings table — add Source column

Remove the entire `{% if urgent_cves %}` block (lines 178–209 in `dashboard.html`). Remove `urgent_cves` from the view context.

Update the Urgent Findings table:
- Add `Source` column between Type and Severity
- Render `f.source` as a small gray badge (same style as existing `check_type` column)
- Change `{{ f.domain }}` → `{{ f.session.domain }}` (the `f.domain` property returns `f.target` which is host:port for nmap findings, not the apex domain)
- Remove the `Type` (`check_type`) column — Source replaces it
- Final columns: `Finding | Domain | Source | Severity | Detected`

## Implementation

### View changes: `apps/core/dashboard/views.py`

Remove the `urgent_cves` query (lines 83–89) and remove `"urgent_cves"` from the `render()` context dict.

No other view changes needed — `urgent_findings` already uses `select_related("session")` so `f.session.domain` works without extra queries.

### Template changes: `templates/dashboard.html`

**1. Domain status `<thead>`** — replace 4 severity `<th>` elements with 2:

```html
<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Findings</th>
<th class="px-6 py-3 text-center text-xs font-medium text-yellow-600 uppercase">Δ New</th>
```

**2. Domain status `<tbody>` row** — replace the 4 severity `<td>` cells with:

```html
<td class="px-6 py-4 text-sm">
  {% if item.summary %}
  <div class="flex flex-wrap gap-1">
    {% if item.summary.critical_count %}
    <a href="{% url 'finding-list' %}?session_id={{ item.latest_session.id }}&severity=critical"
       class="bg-red-50 text-red-600 text-xs font-semibold px-1.5 py-0.5 rounded hover:underline">
      {{ item.summary.critical_count }} crit</a>
    {% endif %}
    {% if item.summary.high_count %}
    <a href="{% url 'finding-list' %}?session_id={{ item.latest_session.id }}&severity=high"
       class="bg-orange-50 text-orange-600 text-xs font-semibold px-1.5 py-0.5 rounded hover:underline">
      {{ item.summary.high_count }} high</a>
    {% endif %}
    {% if item.summary.medium_count %}
    <a href="{% url 'finding-list' %}?session_id={{ item.latest_session.id }}&severity=medium"
       class="bg-yellow-50 text-yellow-700 text-xs font-semibold px-1.5 py-0.5 rounded hover:underline">
      {{ item.summary.medium_count }} med</a>
    {% endif %}
    {% if item.summary.low_count %}
    <a href="{% url 'finding-list' %}?session_id={{ item.latest_session.id }}&severity=low"
       class="bg-slate-100 text-slate-600 text-xs font-semibold px-1.5 py-0.5 rounded hover:underline">
      {{ item.summary.low_count }} low</a>
    {% endif %}
  </div>
  {% else %}
  <span class="text-gray-300">—</span>
  {% endif %}
</td>
<td class="px-6 py-4 text-center">
  {% if item.summary.new_exposures %}
  <span class="bg-yellow-100 text-yellow-800 text-xs font-semibold px-2 py-0.5 rounded-full">
    +{{ item.summary.new_exposures }}
  </span>
  {% else %}
  <span class="text-gray-300 text-sm">—</span>
  {% endif %}
</td>
```

**3. Remove urgent CVEs block** — delete the entire `{% if urgent_cves %}...{% endif %}` section.

**4. Update urgent findings table headers** — replace `Type` `<th>` with `Source`:

```html
<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Finding</th>
<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Domain</th>
<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Detected</th>
```

**5. Update urgent findings table row** — replace `check_type` cell with `source`, fix domain cell:

```html
<tr class="hover:bg-gray-50">
  <td class="px-6 py-3 text-sm text-gray-800 max-w-xs truncate">{{ f.title }}</td>
  <td class="px-6 py-3 text-sm font-mono text-gray-600">{{ f.session.domain }}</td>
  <td class="px-6 py-3 text-xs text-gray-500 uppercase">{{ f.source }}</td>
  <td class="px-6 py-3">{% include "partials/severity_badge.html" with severity=f.severity %}</td>
  <td class="px-6 py-3 text-sm text-gray-500">{{ f.discovered_at|date:"M d, H:i" }}</td>
</tr>
```

## Files Changed

| File | Change |
|---|---|
| `apps/core/dashboard/views.py` | Remove `urgent_cves` query and context var |
| `templates/dashboard.html` | Replace 4 severity columns with badges + Δ New; remove CVE table; update urgent findings columns |

## Testing

**File:** `tests/unit/test_core.py`

Add new class `TestDashboardRedesign`:

- `test_delta_new_shown_when_positive` — domain with `new_exposures=3` → "+3" in response
- `test_delta_new_shows_dash_when_zero` — domain with `new_exposures=0` → "—" in delta cell (no yellow badge)
- `test_urgent_cves_not_in_context` — `"urgent_cves"` not a key in `resp.context`
- `test_urgent_findings_shows_source_column` — response contains `b"Source"` header in urgent findings table
- `test_domain_table_no_separate_crit_column` — response does not contain `b">Crit<"` as a table header
- `test_inline_badges_shown_for_domain_with_findings` — domain with critical_count=2 → `b"2 crit"` in response

Existing tests must continue to pass.

## Non-Goals

- Changes to the top 8 summary cards (state + assets)
- Sorting or filtering in the domain status table
- Pagination of urgent findings
- Any changes to scan detail, findings list, or other pages
