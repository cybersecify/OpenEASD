# React + Tailwind Redesign — Design Spec

**Date:** 2026-04-18
**Status:** Approved

---

## Goal

Replace the unstyled React skeleton with a production-quality dark-themed SPA that
matches the visual quality of the existing HTMX templates. Add Tailwind CSS via npm,
create a shared `Layout` component, redesign all pages, add missing functionality,
and retire the HTMX/Alpine template stack.

---

## 1. Tailwind CSS Setup

**Approach: npm + PostCSS** (Option B — proper setup, small prod bundle).

Files to create:
- `frontend/tailwind.config.js` — content paths scan `./src/**/*.{js,jsx}`
- `frontend/postcss.config.js` — `tailwindcss` + `autoprefixer` plugins
- `frontend/src/index.css` — three Tailwind directives (`@tailwind base/components/utilities`)

Custom theme values (extending Tailwind defaults):
```js
theme: {
  extend: {
    colors: { brand: '#30c074' },
    fontFamily: { sans: ['Inter', 'system-ui', 'sans-serif'] },
  }
}
```

`index.css` also sets `body { background: #060606; }` and the radial green glow
`background-image: radial-gradient(ellipse at 70% -10%, rgba(48,192,116,0.06) 0%, transparent 55%)`.

Dev dependency install: `tailwindcss postcss autoprefixer` + `@tailwindcss/forms` (optional,
for input resets).

---

## 2. Shared Layout Component

`frontend/src/components/Layout.jsx` — wraps every authenticated page.

### Sidebar (fixed, w-56)
- Background `#0a0a0a`, right border `border-white/10`
- **Logo row:** `⬡ OpenEASD` in white bold, hex icon in `#30c074`
- **Nav items** (Dashboard, Domains, Scans, Findings, Insights, Workflows):
  - Each has a Heroicon-style inline SVG (3.5×3.5)
  - Inactive: `text-white/30 border-transparent`, hover `text-white/70`
  - Active: `bg-[rgba(48,192,116,0.08)] text-white border-[#30c074]` left border
  - "Scans" shows animated blue dot + count if any active scans
  - "Findings" shows red badge with critical+high count
- **User/logout row** at bottom: `text-white/40 text-xs` username + Logout button

Active state determined by `window.location.pathname` prefix match passed in from `App.jsx`.

### Main area (ml-56)
- **Header** (`px-8 pt-7 pb-0`): page title (bold, text-xl) + subtitle (text-white/35 text-xs)
  + optional "New Scan" green button (top-right, only on Dashboard)
- **Content** (`px-8 py-6`): `max-w-7xl mx-auto`

### Usage
```jsx
<Layout title="Dashboard" subtitle="Attack surface overview • Apr 18, 2026" action={<NewScanButton/>}>
  {/* page content */}
</Layout>
```

The `Layout` component calls `GET /api/dashboard/` (or a dedicated `/api/sidebar/` — same
data) to populate the badge counts. It re-fetches on route change.

---

## 3. Shared UI Components

### Badge (`src/components/Badge.jsx`)
Color map covers severity (`critical/high/medium/low/info`) and status
(`completed/running/failed/cancelled/pending`). Returns a `<span>` with pill styling.
Already exists — needs Tailwind classes replacing inline styles.

### Pagination (`src/components/Pagination.jsx`)
Prev/Next buttons + "Page N of M" text. Styled: `bg-[#111] border border-white/8
rounded-lg px-3 py-1.5 text-xs`. Disabled state `opacity-40 cursor-not-allowed`.

### ConfirmButton (`src/components/ConfirmButton.jsx`)
Inline two-step: first click shows `<span>` with "Are you sure?" + Confirm/Cancel links
(no browser `confirm()`). Styled in red. Already exists — needs styling.

### Spinner (`src/components/Spinner.jsx`) *(new)*
Small animated ring for loading states. Used inside page content area, not full-screen.

---

## 4. Pages

All pages use `<Layout>` wrapper. Data fetched via `useFetch` or `usePolling` hooks.

### LoginPage
- Centered card on dark background (no sidebar — Layout has an `noSidebar` prop)
- `⬡ OpenEASD` logo above form
- Email + password inputs, Sign In button in brand green
- Submits `POST /api/auth/login/`, navigates to `/` on success

### DashboardPage
- 4 KPI cards row: Critical (red), High (orange), Running Scans (blue), Active Domains (green)
- 4 asset count cards: Subdomains, IP Addresses, Open Ports, Web URLs
- Domain Status table: domain · last scan · status badge · critical · high · View Scan link
- Urgent Findings table (critical + high): severity · title · source · target
- "New Scan" button in Layout header navigates to `/scans/start`

### DomainsPage
- Add Domain form (inline, top of page) — domain name input + Add button
- Domains table: domain · added · active toggle · Delete (ConfirmButton)
- Toggle calls `POST /api/domains/<pk>/toggle/`
- Delete calls `POST /api/domains/<pk>/delete/`

### ScanStartPage *(new — was missing)*
Route: `/scans/start`
- Select domain (dropdown from `/api/domains/`)
- Select workflow (dropdown from `/api/workflows/`)
- Start Scan button → `POST /api/scans/start/` → navigates to `/scans/<uuid>`

### ScansPage
- Filter bar: domain, status dropdowns
- Scans table: domain · started · status · duration · findings (crit/high) · Stop · View
- Stop calls `POST /api/scans/<uuid>/stop/` (only shown when status=running)
- Pagination

### ScanDetailPage
- Header: domain name, started time, status badge, Stop button (if running)
- Progress: workflow steps table with status per step (live-polled every 3s via `usePolling`)
- Asset counts: subdomains, IPs, ports, URLs
- Findings table (all findings from this scan): severity · title · source · target

### FindingsPage
- Filter bar: severity, domain, status, source dropdowns
- Findings table: severity · title · source · target · scan date · status
- Inline status update (acknowledged/false_positive) via `POST /api/scans/findings/<id>/status/`
- Pagination

### WorkflowsPage
- Create form: name input + tool checkboxes (from `/api/workflows/tools/`)
- Workflows table: name · tools count · created · View/Delete
- Delete via ConfirmButton

### WorkflowDetailPage
- Workflow name (editable)
- Tool steps: enable/disable toggles, dependency warnings
- Save + Delete (ConfirmButton) buttons

### InsightsPage
- Findings over time: line chart (Chart.js, loaded via CDN script tag in this page only)
- Severity breakdown: doughnut chart
- Tool breakdown table: tool · findings count
- Top finding types table

---

## 5. Bug Fixes (from audit)

| # | Issue | Fix |
|---|---|---|
| 1 | No `ScanStartPage` | Create page + add `/scans/start` route in `App.jsx` |
| 2 | No sidebar / shared navigation | `Layout.jsx` component wraps all pages |
| 3 | `usePolling` missing 401 redirect | Add same redirect logic as `useFetch` |
| 4 | No logout functionality | Logout button in Layout calls `POST /api/auth/logout/` then navigates to `/login` |
| 5 | No Stop Scan button in ScansPage | Add Stop button, calls `POST /api/scans/<uuid>/stop/` |
| 6 | Pagination unstyled | Tailwind styling in `Pagination.jsx` |
| 7 | ConfirmButton unstyled | Tailwind styling in `ConfirmButton.jsx` |
| 8 | `/scans/start` route missing in `App.jsx` | Add before `/scans/:uuid` to avoid conflict |
| 9 | InsightsPage loads Chart.js globally | Move `<script>` tag to InsightsPage render only |

---

## 6. App Router (`App.jsx`)

Route order matters — static paths before dynamic:
```
/login           → LoginPage      (no layout auth check)
/                → DashboardPage
/domains         → DomainsPage
/scans           → ScansPage
/scans/start     → ScanStartPage   ← BEFORE /scans/:uuid
/scans/:uuid     → ScanDetailPage
/findings        → FindingsPage
/workflows       → WorkflowsPage
/workflows/:id   → WorkflowDetailPage
/insights        → InsightsPage
```

Unauthenticated requests from `useFetch` return 401 → redirect to `/login`.
`App.jsx` also exports a `navigate(path)` helper for imperative navigation.

---

## 7. HTMX Retirement

After all React pages are working and verified:

1. Remove Django templates directory (`templates/`)
2. Remove HTMX + Alpine view functions from Django views files
3. Remove `django_htmx` from `INSTALLED_APPS` and `MIDDLEWARE`
4. Remove `django-htmx` from `pyproject.toml`
5. Keep Django admin (`/admin/`) — it has its own templates, unaffected
6. Update `openeasd/urls.py`: remove template view routes; keep `/api/`, `/admin/`,
   `/accounts/` (Django auth), and catch-all serving `frontend/dist/index.html`
7. Update `CLAUDE.md` to reflect new stack (no HTMX/Alpine)

Catch-all URL for React SPA (in `openeasd/urls.py`):
```python
from django.views.generic import TemplateView
re_path(r"^(?!api/|admin/|accounts/|static/|media/).*$",
        TemplateView.as_view(template_name="index.html"))
```
`index.html` is served from `frontend/dist/` via `STATICFILES_DIRS`.

---

## 8. Dev Workflow

```bash
# Terminal 1 — Django API
uv run manage.py runserver

# Terminal 2 — React (hot reload, proxies /api/ to Django)
cd frontend && npm run dev
# Browse at http://localhost:5173
```

Production:
```bash
cd frontend && npm run build   # outputs to frontend/dist/
uv run manage.py collectstatic
uv run manage.py runserver     # serves React SPA from /
```

---

## 9. Files Changed / Created

| File | Change |
|---|---|
| `frontend/tailwind.config.js` | New — Tailwind config |
| `frontend/postcss.config.js` | New — PostCSS config |
| `frontend/src/index.css` | Update — add Tailwind directives + body styles |
| `frontend/package.json` | Update — add tailwindcss, postcss, autoprefixer |
| `frontend/src/components/Layout.jsx` | New — sidebar + header wrapper |
| `frontend/src/components/Badge.jsx` | Update — Tailwind styling |
| `frontend/src/components/Pagination.jsx` | Update — Tailwind styling |
| `frontend/src/components/ConfirmButton.jsx` | Update — Tailwind two-step confirm |
| `frontend/src/components/Spinner.jsx` | New — loading indicator |
| `frontend/src/App.jsx` | Update — add /scans/start route, fix order |
| `frontend/src/hooks/usePolling.js` | Update — add 401 redirect |
| `frontend/src/pages/LoginPage.jsx` | Update — Tailwind styling |
| `frontend/src/pages/DashboardPage.jsx` | Update — match mockup |
| `frontend/src/pages/DomainsPage.jsx` | Update — Tailwind styling |
| `frontend/src/pages/ScanStartPage.jsx` | New — was missing |
| `frontend/src/pages/ScansPage.jsx` | Update — Tailwind + Stop button |
| `frontend/src/pages/ScanDetailPage.jsx` | Update — Tailwind styling |
| `frontend/src/pages/FindingsPage.jsx` | Update — Tailwind styling |
| `frontend/src/pages/WorkflowsPage.jsx` | Update — Tailwind styling |
| `frontend/src/pages/WorkflowDetailPage.jsx` | Update — Tailwind styling |
| `frontend/src/pages/InsightsPage.jsx` | Update — Tailwind + scoped Chart.js |
| `openeasd/urls.py` | Update — add SPA catch-all (after HTMX retirement) |
| `templates/` | Delete — retired (after HTMX retirement phase) |
| `CLAUDE.md` | Update — reflect new React+Tailwind stack |
