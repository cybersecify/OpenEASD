# Scans Page UI Redesign

**Date:** 2026-04-13
**Status:** Approved
**Scope:** `apps/core/scans/views.py`, `apps/core/scans/templatetags/scan_tags.py` (new), `templates/scans/list.html`, `templates/partials/scan_rows.html`

## Problem

The scans page has no summary context — you land on it with no sense of how many scans are running, completed, or failed. The "Started" column shows only a timestamp; there's no way to see at a glance how long a scan took or how long a running scan has been going.

## Goal

Add 3 clickable status summary cards at the top (Running / Completed / Failed). Replace the "Started" column with a "When" column showing start time + a duration sub-line. No other changes to layout or functionality.

## Design

### Status Summary Cards

Three cards across the full width, counting all scans (not filtered):

| Card | Value | Query |
|---|---|---|
| Running | `count_running` | `ScanSession.objects.filter(status="running").count()` |
| Completed | `count_completed` | `ScanSession.objects.filter(status="completed").count()` |
| Failed | `count_failed` | `ScanSession.objects.filter(status="failed").count()` |

Cards are `<a>` links to `?status=X`. When `status_filter == 'X'`, the card gets a colored ring (`ring-2 ring-{color}-400`).

Card styling:
- Running: blue border (`border-blue-200`), blue number, ring `ring-blue-400`
- Completed: green border (`border-green-200`), green number, ring `ring-green-400`
- Failed: red border (`border-red-200`), red number, ring `ring-red-400`

Label text: "active scans" / "finished scans" / "errored scans".

### "When" Column

Replaces the "Started" column in the scan history table. Two stacked lines per cell:

1. **Top line:** `start_time` formatted as `M d, Y H:i` (same as current "Started")
2. **Bottom line:** Duration label (muted `text-slate-400 text-xs`):
   - `running` status → `"running Xm Ys"` (elapsed since start, computed at render time)
   - `completed` status → `"took Xm Ys"`
   - `failed` status → `"after Xm Ys"`
   - `pending` / `cancelled` / no `end_time` → nothing (bottom line omitted)

Duration is computed by a custom template filter `scan_duration_label` in a new templatetags file.

## Implementation

### New file: `apps/core/scans/templatetags/scan_tags.py`

```python
from django import template
from django.utils import timezone

register = template.Library()


@register.filter
def scan_duration_label(scan):
    """Return a human-readable duration string for the scan's When column."""
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

### View changes: `apps/core/scans/views.py` — `scan_list`

Add 3 count queries before the `render()` call, and pass them to the full-page render context. Do **not** add them to the HTMX partial render.

```python
count_running   = ScanSession.objects.filter(status="running").count()
count_completed = ScanSession.objects.filter(status="completed").count()
count_failed    = ScanSession.objects.filter(status="failed").count()
```

Pass as: `"count_running"`, `"count_completed"`, `"count_failed"`.

### Template changes: `templates/scans/list.html`

1. Add 3-card grid above the scheduled jobs section (before the `{% if scheduled %}` block).
2. Replace the "Started" `<th>` with "When".

### Partial changes: `templates/partials/scan_rows.html`

1. Load `scan_tags` at top: `{% load scan_tags %}`
2. Replace the Started `<td>` (`{{ scan.start_time|date:"M d, Y H:i" }}`) with a "When" cell:

```html
<td class="px-6 py-4 text-sm">
  <div class="text-gray-500">{{ scan.start_time|date:"M d, Y H:i" }}</div>
  {% with label=scan|scan_duration_label %}
  {% if label %}<div class="text-xs text-slate-400">{{ label }}</div>{% endif %}
  {% endwith %}
</td>
```

## Files Changed

| File | Change |
|---|---|
| `apps/core/scans/templatetags/__init__.py` | New empty file (makes templatetags a package) |
| `apps/core/scans/templatetags/scan_tags.py` | New — `scan_duration_label` filter |
| `apps/core/scans/views.py` | Add 3 `count_*` context vars to full-page render |
| `templates/scans/list.html` | Add status cards, replace Started `<th>` with When |
| `templates/partials/scan_rows.html` | Load scan_tags, replace Started `<td>` with When cell |

## Testing

**File:** `tests/unit/test_scans.py`

Add a new test class `TestScanListCards`:
- `test_count_vars_in_context` — view returns `count_running`, `count_completed`, `count_failed` in context
- `test_count_running_counts_correctly` — only running sessions counted
- `test_count_completed_excludes_running` — running sessions not in completed count
- `test_status_card_links_present` — rendered page includes `?status=running`, `?status=completed`, `?status=failed` links
- `test_selected_card_has_ring` — `?status=completed` → page contains `ring-green-400`

Add a new test class `TestScanDurationLabel` (unit tests for the template filter):
- `test_completed_scan_returns_took` — completed scan with end_time returns `"took Xm Ys"`
- `test_failed_scan_returns_after` — failed scan returns `"after Xm Ys"`
- `test_running_scan_returns_running` — running scan returns `"running Xm Ys"`
- `test_pending_scan_returns_empty` — pending scan returns `""`
- `test_no_end_time_returns_empty` — completed scan with no end_time returns `""`
- `test_sub_minute_duration` — duration under 60s formats as seconds only (e.g., `"took 45s"`)

Existing tests must continue to pass.

## Non-Goals

- Live-updating elapsed time for running scans (static at render time is fine)
- Changes to scheduled jobs section
- Changes to scan detail page
- Changes to delete/cancel actions
- Mobile responsiveness
