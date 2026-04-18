# URLs Tab Enhancement — Design Spec
**Date:** 2026-04-18  
**Status:** Approved

## Summary

Enhance the existing `urls` tab in `ScanDetailPage.jsx` to display all fields returned by the httpx tool, with client-side scheme and status-code filtering.

## Scope

- **One file changed:** `frontend/src/pages/ScanDetailPage.jsx`
- **No new routes, pages, or API endpoints** (the tab already exists; data already arrives via `GET /api/scans/<uuid>/`)
- **No new components** — scheme badge rendered inline; `fmtSize` helper added locally

## Columns

| Column | Field | Rendering |
|---|---|---|
| Scheme | `scheme` | Inline badge: `https` → blue, `http` → amber |
| URL | `url` | Truncated monospace link, opens in new tab (`target="_blank"`) |
| Status | `status_code` | Coloured number: 2xx green, 3xx yellow, 4xx orange, 5xx red; `—` if null |
| Title | `title` | Plain text, truncated, `—` if empty |
| Server | `web_server` | Dim text, `—` if empty |
| Size | `content_length` | Human-readable via `fmtSize()`, `—` if null |

## Filters

Two controls rendered above the table when the `urls` tab is active:

| Filter | Type | Behaviour |
|---|---|---|
| Scheme | Dropdown | Options: All / https / http |
| Status code | Text input | Prefix match: `"2"` matches all 2xx, `"404"` exact |

Both filters are `useState('')` local to the component, reset to `''` when the tab changes (via the existing `setTab` handler), and reset pagination to page 1 on change.

Filtering is applied client-side on `data.urls` before slicing for pagination.

## Size Formatter

```js
function fmtSize(bytes) {
  if (bytes == null) return '—';
  if (bytes === 0)   return '0 B';
  if (bytes < 1024)  return `${bytes} B`;
  if (bytes < 1_048_576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1_048_576).toFixed(1)} MB`;
}
```

## Status Code Colouring

```js
function statusColor(code) {
  if (!code) return 'text-dim';
  if (code < 300) return 'text-green-400';
  if (code < 400) return 'text-yellow-400';
  if (code < 500) return 'text-orange-400';
  return 'text-red-400';
}
```

## Scheme Badge Style Map

Rendered inline (not via `Badge` component — keeps `Badge` focused on severity/status values):

```js
const SCHEME_CLS = {
  https: 'bg-blue-900/40 text-blue-400 border border-blue-800',
  http:  'bg-yellow-900/40 text-yellow-400 border border-yellow-800',
};
```

## Empty States

- No URLs, no active filters: `"No URLs discovered yet."`
- Filters produce no matches: `"No URLs match the current filters."` — filter controls remain visible

## What Is Not Changing

- Pagination (50 per page, existing `Pagination` component)
- Other tabs (subdomains, ips, ports, findings) — untouched
- `api_url_list` endpoint (`GET /api/scans/urls/`) — already added, available for future standalone page
- No tests required — pure render logic on already-fetched data, consistent with all other tabs
