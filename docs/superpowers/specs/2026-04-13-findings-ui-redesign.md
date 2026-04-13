# Findings Page UI Redesign

**Date:** 2026-04-13
**Status:** Approved
**Scope:** `templates/findings/list.html`, `templates/partials/vuln_rows.html`, `apps/core/scans/views.py`

## Problem

The findings page is a flat table with no summary context. You land on it with no sense of how many open critical or high findings exist. The domain column takes up space but is redundant when the page already has a domain filter. The "View Scan" link text wastes column width.

## Goal

Add 4 clickable severity summary cards at the top to give immediate triage context. Slim the table from 7 to 5 columns by removing domain and replacing the scan link text with a small ↗ icon.

## Design

### Summary Cards

Four cards across the full width, counting **open findings only** across all latest sessions:

| Card | Value | Query |
|---|---|---|
| Critical | `count_open_critical` | `Finding.objects.filter(session_id__in=latest_session_ids(), status="open", severity="critical").count()` |
| High | `count_open_high` | `Finding.objects.filter(session_id__in=latest_session_ids(), status="open", severity="high").count()` |
| Medium | `count_open_medium` | `Finding.objects.filter(session_id__in=latest_session_ids(), status="open", severity="medium").count()` |
| Low | `count_open_low` | `Finding.objects.filter(session_id__in=latest_session_ids(), status="open", severity="low").count()` |

Cards are simple `<a>` links to `?severity=X`. When `severity == 'X'` in context, the card gets a colored ring (`ring-2 ring-{color}-400`).

Card styling:
- Critical: red border (`border-red-200`), red number, ring `ring-red-400`
- High: orange border (`border-orange-200`), orange number, ring `ring-orange-400`
- Medium: yellow border (`border-yellow-200`), yellow number, ring `ring-yellow-400`
- Low: blue border (`border-blue-200`), blue number, ring `ring-blue-400`

### Table Changes

Remove the Domain column (`<th>` and `<td>`). Replace the scan link column header (currently blank `<th>`) with nothing — keep the column for the ↗ icon. Replace `<a href="...">View Scan</a>` with `<a href="..." class="text-indigo-500 hover:text-indigo-700" title="View scan">↗</a>`. Update `colspan="7"` on the empty row to `colspan="6"`.

### Filter Bar

Unchanged. Domain text input, severity select, status select remain as-is.

## View Changes

**File:** `apps/core/scans/views.py` — `vulnerability_list` function

Add 4 count queries after `latest_ids = latest_session_ids()` (reuse the result):

```python
count_open_critical = Finding.objects.filter(session_id__in=latest_ids, status="open", severity="critical").count()
count_open_high     = Finding.objects.filter(session_id__in=latest_ids, status="open", severity="high").count()
count_open_medium   = Finding.objects.filter(session_id__in=latest_ids, status="open", severity="medium").count()
count_open_low      = Finding.objects.filter(session_id__in=latest_ids, status="open", severity="low").count()
```

Pass all four to the full-page render context. **Do not** add them to the HTMX partial render (the cards are not part of `vuln_rows.html`).

## Template Changes

**File:** `templates/findings/list.html`

1. Add 4-card grid above the existing filter form, inside the page content area.
2. Remove the Domain `<th>` from the table header.

**File:** `templates/partials/vuln_rows.html`

1. Remove the domain `<td>` (`{{ vuln.session.domain }}`).
2. Replace `<a href="...">View Scan</a>` with `<a href="..." ...>↗</a>`.
3. Update empty state `colspan="7"` → `colspan="6"`.

## Files Changed

| File | Change |
|---|---|
| `apps/core/scans/views.py` | Add 4 `count_open_*` context vars to full-page render |
| `templates/findings/list.html` | Add severity cards, remove Domain `<th>` |
| `templates/partials/vuln_rows.html` | Remove domain `<td>`, icon-ify scan link, fix colspan |

## Testing

**File:** `tests/unit/test_scans.py`

Add a new test class `TestFindingsPageCards`:
- `test_count_vars_in_context` — view returns all 4 `count_open_*` keys in context
- `test_count_open_critical_excludes_resolved` — resolved critical findings not counted
- `test_count_open_critical_excludes_acknowledged` — acknowledged critical findings not counted
- `test_count_open_high_counts_correctly` — open high findings counted correctly
- `test_severity_card_link_present` — rendered page HTML includes `?severity=critical` link
- `test_selected_card_has_ring` — when `?severity=critical`, critical card has ring class

Existing tests must continue to pass.

## Non-Goals

- Changes to filter behavior or HTMX partial logic
- Changes to the status inline-edit cell
- Mobile responsiveness
- Pagination changes
- Scans page redesign (separate effort)
