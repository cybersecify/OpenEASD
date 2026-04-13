# Domains Page UI Redesign

**Date:** 2026-04-13
**Status:** Approved
**Scope:** `apps/core/domains/views.py`, `templates/domains/list.html`

## Problem

The domains table's "Added" column wastes space on a date that tells you nothing actionable. There's no way to see at a glance when a domain was last scanned or whether it has open findings — you have to navigate away to the scans or findings page.

## Goal

Replace the "Added" column with a "Last Scan" column (date + status sub-text) and add a "Findings" column (non-zero severity badges for open findings from the latest completed scan). Table goes from 5 to 6 columns. No other layout or functionality changes.

## Design

### Last Scan Column

Shows the most recent `ScanSession` for the domain regardless of status (so a currently-running scan shows as "running"):

- **Top line:** `start_time` formatted as `M d, Y H:i`
- **Bottom line:** `scan.status` in muted text (`text-slate-400 text-xs`)
- **If no sessions exist:** "Never scanned" in italic muted text

### Findings Column

Shows open findings from the latest **completed** session only (using `latest_session_ids()`):

- Severity badges rendered only for non-zero counts: critical, high, medium, low (info excluded — not actionable)
- Badge styling matches the findings page: red for critical, orange for high, yellow for medium, slate for low
- "—" if the domain has no completed scan or zero open findings at those severities
- `status="open"` filter applied — resolved and acknowledged findings excluded

### Column layout

`Domain | Type | Status | Last Scan | Findings | Actions` (6 columns)

The confirm-delete inline row `colspan` updates from 5 → 6.

## Implementation

### View changes: `apps/core/domains/views.py`

Extract a module-level helper `_enrich_domains(domains)` that attaches `last_scan` and `findings_summary` to each domain object in-place. Call it in both `domain_list` (main path) and `domain_delete` (the error render path at line ~66 that also renders `list.html`).

```python
from django.db.models import Count
from apps.core.queries import latest_session_ids
from apps.core.findings.models import Finding


def _enrich_domains(domains):
    """Attach last_scan and findings_summary to each Domain object."""
    domain_names = [d.name for d in domains]
    if not domain_names:
        for domain in domains:
            domain.last_scan = None
            domain.findings_summary = {}
        return

    # Latest session per domain (any status)
    latest_sessions = {}
    for session in ScanSession.objects.filter(
        domain__in=domain_names
    ).order_by("domain", "-start_time"):
        if session.domain not in latest_sessions:
            latest_sessions[session.domain] = session

    # Open findings from latest completed session per domain
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
```

In `domain_list`: call `_enrich_domains(domains)` after `domains = Domain.objects.all()`.

In `domain_delete` error path: call `_enrich_domains(domains)` after `domains = Domain.objects.all()` in the active-scan guard block.

### Template changes: `templates/domains/list.html`

1. Replace `<th>Added</th>` with `<th>Last Scan</th>`, add `<th>Findings</th>` before Actions `<th>`.

2. Replace the Added `<td>` cell with:

```html
<td class="px-6 py-4 text-sm">
  {% if domain.last_scan %}
  <div class="text-gray-500">{{ domain.last_scan.start_time|date:"M d, Y H:i" }}</div>
  <div class="text-xs text-slate-400">{{ domain.last_scan.status }}</div>
  {% else %}
  <span class="text-gray-400 italic">Never scanned</span>
  {% endif %}
</td>
```

3. Add new Findings `<td>` before the Actions cell:

```html
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
```

4. Update confirm-delete row `colspan="5"` → `colspan="6"`.

## Files Changed

| File | Change |
|---|---|
| `apps/core/domains/views.py` | Attach `last_scan` and `findings_summary` to each domain object |
| `templates/domains/list.html` | Replace Added column, add Last Scan + Findings columns, update colspan |

## Testing

**File:** `tests/unit/test_domains.py`

Add new test class `TestDomainListEnrichment`:

- `test_last_scan_attached` — domain with a completed scan has `last_scan` set (correct session)
- `test_never_scanned_domain_has_no_last_scan` — domain with no sessions: `last_scan` is `None`, page shows "Never scanned"
- `test_last_scan_shows_any_status` — a running scan (not just completed) appears as the last scan
- `test_findings_summary_counts` — domain with open critical + high findings: summary dict has correct counts
- `test_findings_excludes_resolved` — resolved findings not in summary
- `test_findings_excludes_info` — info-severity findings not in summary
- `test_findings_empty_when_no_completed_scan` — domain with only a running scan: findings summary is empty dict
- `test_findings_column_shows_dash_when_clean` — rendered page contains "—" for domain with no open findings
- `test_confirm_delete_colspan_is_6` — rendered page contains `colspan="6"`

Existing tests must continue to pass.

## Non-Goals

- Sorting or filtering by findings count
- Clickable findings badges (linking to filtered findings page)
- Live-updating scan status
- Mobile responsiveness changes
- Any changes to Add Domain form or domain actions
