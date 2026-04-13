# Insights Layout Redesign

**Date:** 2026-04-13
**Status:** Approved
**Scope:** `templates/insights.html`, `apps/core/insights/views.py`

## Problem

The insights page has 8 sections of data in no deliberate order. It doesn't answer any single question — it just lists all available data. When you open it, you have to scan the whole page to orient yourself.

## Goal

Reorganize the insights page into a top-to-bottom narrative that answers the three questions a solo security dev asks: *Am I getting worse or better? Is my remediation working? Where should I focus next?*

No new data sources. No new models. Pure layout and view cleanup.

## Design

### KPI Row (top of page)

Four cards across the full width, drawn from data already in the view:

| Card | Value | Source |
|---|---|---|
| Open Critical | `kpi_open_critical` | `Finding.objects.filter(severity="critical", status="open").count()` |
| Open High | `kpi_open_high` | `Finding.objects.filter(severity="high", status="open").count()` |
| New This Scan | `kpi_new` | `summaries[-1].new_exposures` (most recent summary, 0 if no scans) |
| Fixed This Scan | `kpi_fixed` | `summaries[-1].removed_exposures` (most recent summary, 0 if no scans) |

Card styling: white background, colored border — red for critical, orange for high, green for new, blue for fixed. Empty state: all four cards show `0` if no scans.

### Section 1 — Security Posture (indigo left border)

Subheading: *"Finding severity across your last 10 scans"*

Content: The existing finding trend table (full width). Columns: Scan, Critical, High, Medium, Low, Distribution bar. No changes to the data or table markup — only placement changes.

### Section 2 — Remediation Progress (green left border)

Subheading: *"New exposures introduced vs. findings fixed per scan"*

Two-column layout:
- **Left:** Existing new/fixed delta table (Scan, New, Fixed)
- **Right:** Existing recurring finding types list (top 10, title + check_type + severity badge + occurrence count)

No changes to data or markup — only placement changes.

### Section 3 — Where to Focus (orange left border)

Subheading: *"Top vulnerable domains and services from latest scans"*

Two-column layout:
- **Left:** Existing top vulnerable domains (indigo bar chart)
- **Right:** Existing top vulnerable services table (Service, Version, CVEs, Max CVSS)

No changes to data or markup — only placement changes.

### Section 4 — Asset Coverage (slate left border)

Subheading: *"Growth of discovered subdomains, IPs, ports, and URLs over time"*

Two-column layout (2/3 + 1/3):
- **Left (2/3):** Existing asset growth Chart.js line chart
- **Right (1/3):** Existing findings-by-tool card grid + existing CVE severity doughnut chart (stacked vertically)

No changes to data, chart code, or markup — only placement changes.

### Section headers

Each section header follows this pattern:
```html
<div class="flex items-center gap-2 mb-4">
  <div class="w-0.5 h-4 bg-{color}-500 rounded"></div>
  <h2 class="text-sm font-semibold text-slate-900">Section Title</h2>
  <span class="text-xs text-slate-400">Subtitle describing the data</span>
</div>
```

Colors: `indigo-500` / `green-500` / `orange-500` / `slate-500`

### Empty state

Unchanged from current: shown when `scan_trend` is empty, links to "Start a Scan".

## View Changes

**File:** `apps/core/insights/views.py`

Add four KPI values to the render context. Two new DB queries (both `.count()`, both hit indexed fields):

```python
kpi_open_critical = Finding.objects.filter(severity="critical", status="open").count()
kpi_open_high = Finding.objects.filter(severity="high", status="open").count()
kpi_new = summaries[-1].new_exposures if summaries else 0
kpi_fixed = summaries[-1].removed_exposures if summaries else 0
```

Pass as: `"kpi_open_critical"`, `"kpi_open_high"`, `"kpi_new"`, `"kpi_fixed"`.

All existing context variables remain unchanged.

## Template Changes

**File:** `templates/insights.html`

Full restructure of body content. All existing HTML blocks (tables, charts, lists) are preserved — only their order and surrounding wrappers change. Specific changes:

1. Add KPI card row before all sections
2. Wrap each section in a `<div>` with section header markup
3. Reorder sections: Posture → Remediation → Focus → Coverage
4. Move tool breakdown card grid from standalone section into Asset Coverage right column

## Files Changed

| File | Change |
|---|---|
| `apps/core/insights/views.py` | Add 4 KPI context variables; two new `.count()` queries |
| `templates/insights.html` | Restructure into 4 labeled sections + KPI row |

## Non-Goals

- New charts or data sources
- Filtering or interactive features
- Mobile responsiveness
- Changes to models or `builder.py`
- Changes to any other template

## Testing

Update `tests/unit/test_insights.py`:
- Test that view context includes `kpi_open_critical`, `kpi_open_high`, `kpi_new`, `kpi_fixed`
- Test `kpi_open_critical` counts only open critical findings (not resolved/acknowledged)
- Test `kpi_open_high` counts only open high findings
- Test `kpi_new` and `kpi_fixed` come from the most recent scan summary (0 when no scans)
- Existing tests must continue to pass
