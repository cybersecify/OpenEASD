# Sidebar Navigation Design

**Date:** 2026-04-13
**Status:** Approved
**Scope:** `templates/base.html`, new `apps/core/dashboard/context_processors.py`, `openeasd/settings.py`

## Problem

The current top navbar is minimal and gives no at-a-glance security context. There is no indication of open critical findings or active scans unless you navigate to specific pages. As the number of nav items grows, the horizontal top bar becomes cramped.

## Goal

Replace the horizontal top navbar with a slate-black sidebar navigation that:
1. Provides persistent navigation with a clear active state
2. Shows a red badge on Findings with the count of open critical+high findings
3. Shows a pulsing blue dot on Scans when any scan is currently running
4. Pins Logout to the bottom of the sidebar

## Design

### Sidebar

**Dimensions:** Fixed width `w-56` (224px). Full viewport height (`min-h-screen`). Never collapsible (mobile is out of scope — solo dev tool).

**Colors:**
- Background: `#0f172a` (Tailwind `slate-900`)
- Active item background: `#1e293b` (Tailwind `slate-800`)
- Active item left border: `#6366f1` (Tailwind `indigo-500`)
- Inactive link text: `#64748b` (Tailwind `slate-500`)
- Active link text: `white`
- Border separators: `#1e293b` (Tailwind `slate-800`)

**Logo section:** `⬡ OpenEASD` in white bold, bottom border separator.

**Nav links (in order):** Dashboard, Domains, Scans, Findings, Insights, Workflows.

**Active state:** Detected via `request.resolver_match.url_name` in the template — left indigo border + slate-800 background + white text. URL name → nav section mapping:

| URL names | Active section |
|---|---|
| `dashboard` | Dashboard |
| `domain-list`, `domain-toggle`, `domain-delete` | Domains |
| `scan-list`, `scan-detail`, `scan-start`, `scan-status-fragment`, `scan-stop`, `scan-delete`, `scheduled-jobs` | Scans |
| `finding-list`, `finding-update-status` | Findings |
| `insights` | Insights |
| `workflow-list`, `workflow-create`, `workflow-detail`, `workflow-delete`, `workflow-toggle-step` | Workflows |

**Scans link — active scan indicator:**
- Shown only when `sidebar_running_count > 0`
- Pulsing blue dot (`animate-pulse`, `bg-blue-500`, 6px circle) + count number in `text-blue-400`
- Positioned right-aligned within the nav link row

**Findings link — critical+high badge:**
- Shown only when `sidebar_finding_badge > 0`
- Red pill badge (`bg-red-600 text-white`, rounded-full, `text-xs font-bold`)
- Count = open critical findings + open high findings combined
- Positioned right-aligned within the nav link row

**Logout:** Pinned to bottom with top border separator. POST form with CSRF token (same as current implementation).

### Content area

**Layout change:** The `<body>` switches from vertical stack to horizontal flex. Sidebar is the left flex child; `<main>` is the right flex child (`flex-1`).

`<main>` retains: `bg-gray-50`, `px-8 py-8`, `min-h-screen`. Max-width constraint (`max-w-7xl mx-auto`) moves inside `<main>` so it constrains content but not the sidebar.

### Flash messages

Remain inside `<main>`, unchanged.

## Context Processor

**File:** `apps/core/dashboard/context_processors.py`

**Function:** `sidebar_counts(request)`

Returns:
```python
{
    "sidebar_finding_badge": int,   # count of open critical+high findings across all sessions
    "sidebar_running_count": int,   # count of currently running scan sessions
}
```

**Queries (both use `.count()` — no full fetch):**
```python
from apps.core.findings.models import Finding
from apps.core.scans.models import ScanSession

finding_badge = Finding.objects.filter(
    severity__in=["critical", "high"],
    status="open"
).count()

running_count = ScanSession.objects.filter(status="running").count()
```

Registered in `settings.py` under `TEMPLATES[0]["OPTIONS"]["context_processors"]`.

**Performance:** Two `.count()` queries per page load. Both hit indexed fields (`severity`, `status`, `status`). Acceptable for a self-hosted solo dev tool.

## Files Changed

| File | Change |
|---|---|
| `templates/base.html` | Replace `<nav>` top bar with sidebar; restructure body layout |
| `apps/core/dashboard/context_processors.py` | New file — `sidebar_counts` context processor |
| `openeasd/settings.py` | Register context processor in `TEMPLATES` |

## Non-Goals

- Mobile/responsive sidebar (collapse to hamburger) — out of scope
- Sidebar icons (text labels only)
- Collapsible/expandable sidebar
- Per-domain finding counts in the sidebar
- Any changes to page content beyond `base.html`

## Testing

Update `tests/unit/test_core.py`:
- Test `sidebar_counts` returns correct `sidebar_finding_badge` for open critical/high findings
- Test `sidebar_counts` returns 0 badge when no open critical/high findings exist
- Test `sidebar_counts` returns correct `sidebar_running_count` when scans are running
- Test `sidebar_counts` returns 0 running when no scans are running
- Test dashboard view context includes `sidebar_finding_badge` and `sidebar_running_count`
- Existing dashboard tests must continue to pass
