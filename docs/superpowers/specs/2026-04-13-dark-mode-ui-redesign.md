# Dark Mode UI Redesign

**Date:** 2026-04-13
**Status:** Approved
**Scope:** `templates/base.html`, all page templates, all partial templates

## Problem

The current UI uses a light gray background with white cards and an indigo accent. It does not match the cybersecify.com brand palette, uses system fonts with no explicit font loading, and has no consistent dark mode aesthetic suited to a security tool.

## Goal

Apply a full dark mode redesign aligned to the cybersecify.com brand palette:
- Dark green-tinted backgrounds (not slate/navy)
- Brand green `#30c074` as the accent color throughout
- Inter font explicitly loaded via Google Fonts
- Larger, better-weighted typography throughout

No layout changes. No new features. Purely colors, typography, and visual polish.

## Design

### Color Palette

| Role | Current (Tailwind) | New (hex) |
|---|---|---|
| Body background | `bg-gray-50` | `#0a1a0f` |
| Sidebar background | `bg-slate-900` | `#050e08` |
| Card background | `bg-white` | `#0d2614` |
| Table thead background | `bg-gray-50` (inside cards) | `rgba(0,0,0,0.35)` |
| Card border | `border-gray-200` | `rgba(48,192,116,0.12)` |
| Card border (hover/focus) | `border-gray-300` | `rgba(48,192,116,0.22)` |
| Accent | `indigo-500` / `indigo-600` | `#30c074` |
| Accent background tint | `indigo-50` | `rgba(48,192,116,0.10)` |
| Primary text | `text-gray-900` | `#e8f5ef` |
| Secondary text | `text-gray-500` | `#6b9e7e` |
| Muted text | `text-gray-400` | `#3d6b4f` |
| Very muted / inactive | `text-gray-300` | `#1e3d2a` |
| Form input background | `bg-white` | `rgba(0,0,0,0.30)` |
| Form input border | `border-gray-300` | `rgba(48,192,116,0.12)` |
| Focus ring | `ring-indigo-500` | `ring-[#30c074]` / `rgba(48,192,116,0.15)` |
| Table row hover | `hover:bg-gray-50` | `rgba(48,192,116,0.025)` |
| Body radial glow | none | `radial-gradient(ellipse at 70% -10%, rgba(48,192,116,0.07) 0%, transparent 55%)` |

### Severity Colors (dark-adapted)

All severity colors shift from light background + dark text to dark tinted background + pastel text, for readability on dark cards.

| Severity | Badge bg | Badge text |
|---|---|---|
| Critical | `rgba(239,68,68,0.14)` | `#fca5a5` |
| High | `rgba(249,115,22,0.14)` | `#fdba74` |
| Medium | `rgba(234,179,8,0.10)` | `#fde047` |
| Low | `rgba(48,192,116,0.12)` | `#6ee7b7` |
| Info | `rgba(148,163,184,0.10)` | `#94a3b8` |

### Status Colors (dark-adapted)

| Status | Color |
|---|---|
| Running / in-progress | `#93c5fd` (blue-300) on `rgba(59,130,246,0.12)` |
| Completed | `#30c074` (brand green) on `rgba(48,192,116,0.10)` |
| Failed | `#fca5a5` (red-300) on `rgba(239,68,68,0.12)` |

### Typography

Load Inter via Google Fonts in `base.html`:
```html
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
```

Add to `<body>`: `font-family: 'Inter', system-ui, sans-serif;`

Font weight usage:
- Page titles (`h1`): `font-extrabold` (800), `letter-spacing: -0.03em`
- Section headings / card titles: `font-semibold` (600)
- Nav items: `font-medium` (500)
- Body text / table cells: `font-normal` (400)
- Labels / badges: `font-semibold` (600)
- Stat card values: `font-extrabold` (800), `letter-spacing: -0.03em`

### Buttons

| Type | Current | New |
|---|---|---|
| Primary | `bg-indigo-600 hover:bg-indigo-700 text-white` | `bg-[#30c074] hover:bg-[#28a863] text-[#022c22] font-bold` |
| Ghost / outline | `border-gray-300 text-gray-700` | `border-[rgba(48,192,116,0.22)] text-[#30c074]` |
| Danger | `bg-red-600 text-white` | unchanged |

### Nav Active State

```
border-l-2 border-[#30c074] bg-[rgba(48,192,116,0.08)] text-[#e8f5ef]
```

Inactive: `text-[#1e3d2a] hover:text-[#6b9e7e] hover:bg-[rgba(48,192,116,0.04)]`

### Alert / Message Banners

Dark-adapted variants:
- Success: `bg-[rgba(48,192,116,0.10)] border-[rgba(48,192,116,0.25)] text-[#6ee7b7]`
- Error: `bg-[rgba(239,68,68,0.10)] border-[rgba(239,68,68,0.25)] text-[#fca5a5]`
- Warning: `bg-[rgba(234,179,8,0.10)] border-[rgba(234,179,8,0.25)] text-[#fde047]`
- Info: `bg-[rgba(59,130,246,0.10)] border-[rgba(59,130,246,0.25)] text-[#93c5fd]`

## Files Changed

| File | Change |
|---|---|
| `templates/base.html` | Inter font link; body bg/text; sidebar bg; nav active/inactive classes; alert banner classes |
| `templates/dashboard.html` | Card bg/border; table thead; stat card classes; all text colors |
| `templates/domains/list.html` | Card bg/border; form input; table classes; button classes; text colors |
| `templates/scans/list.html` | Card bg/border; status card classes; table classes; text colors |
| `templates/scans/detail.html` | Card bg/border; phase/step list; text colors |
| `templates/scans/start.html` | Form card; input/select classes; button |
| `templates/scans/scheduled.html` | Card bg/border; table classes |
| `templates/findings/list.html` | Severity cards; filter bar inputs/selects; table classes; text colors |
| `templates/insights.html` | Card bg/border; text colors |
| `templates/workflow/list.html` | Card bg/border; table; text colors |
| `templates/workflow/detail.html` | Card bg/border; step list; text colors |
| `templates/partials/severity_badge.html` | Dark tinted bg + pastel text for all 5 levels |
| `templates/partials/status_badge.html` | Dark-adapted status colors |
| `templates/partials/scan_status.html` | Dark-adapted running/completed/failed colors |
| `templates/partials/pagination.html` | Dark-adapted page link colors |
| `templates/registration/login.html` | Dark form card; inputs; button |

## Non-Goals

- No layout changes
- No new features or data
- No Tailwind build step — all colors via Tailwind arbitrary values `bg-[#hex]` or inline `style=`
- No JavaScript changes
- No model or view changes
- No dark mode toggle — dark everywhere, always

## Testing

All existing tests continue to pass (template-only changes, no view logic touched). Manual browser review of each page after implementation.
