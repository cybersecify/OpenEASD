# Frontend JWT Migration Design

**Date:** 2026-04-20
**Project:** OpenEASD
**Scope:** Migrate React frontend from session/CSRF auth to JWT Bearer tokens

---

## Goal

Replace Django session cookie + CSRF token auth with JWT Bearer tokens stored in `localStorage`. Simultaneously fix response shape handling — the backend now returns flat responses (no `{"ok", "data", "errors"}` envelope).

---

## Key Decisions

| Decision | Choice | Reason |
|---|---|---|
| Token storage | `localStorage` | Practical for self-hosted solo tool; persists across refreshes |
| Auth state | No React context | Simple `auth.js` module with localStorage helpers is sufficient |
| Refresh token | Sent on logout only | No auto-refresh on expiry — 401 redirects to login |
| Response shape | Flat (Ninja API) | Remove `res.data` unwrapping; use `res` directly |
| Pagination | Auto-extract from flat response | Preserve existing `pagination.page` interface for pages |

---

## File Changes

| File | Action | Change |
|---|---|---|
| `src/auth.js` | Create | localStorage token helpers |
| `src/api/client.js` | Rewrite | Bearer token, flat response, 401 clear+redirect |
| `src/hooks/useFetch.js` | Modify | `res` direct + auto-extract pagination |
| `src/hooks/usePolling.js` | Modify | `res.data` → `res` |
| `src/pages/LoginPage.jsx` | Modify | Store tokens after login |
| `src/components/Layout.jsx` | Modify | Send refresh token on logout, clear storage |
| `src/App.jsx` | Modify | Login guard before route matching |
| `src/pages/ScansPage.jsx` | Modify | `data?.map` → `data?.results?.map` |

---

## Section 1: Auth Module

**New `src/auth.js`:**

```js
const ACCESS_KEY = 'openeasd_access';
const REFRESH_KEY = 'openeasd_refresh';

export const auth = {
  getToken:   () => localStorage.getItem(ACCESS_KEY),
  getRefresh: () => localStorage.getItem(REFRESH_KEY),
  setTokens:  (access, refresh) => {
    localStorage.setItem(ACCESS_KEY, access);
    localStorage.setItem(REFRESH_KEY, refresh);
  },
  clear: () => {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
  },
  isLoggedIn: () => !!localStorage.getItem(ACCESS_KEY),
};
```

---

## Section 2: client.js Rewrite

**New `src/api/client.js`:**

```js
import { auth } from '../auth.js';

export async function apiFetch(path, options = {}) {
  const token = auth.getToken();
  const isWrite = options.method && options.method !== 'GET' && options.method !== 'HEAD';

  const res = await fetch(`/api${path}`, {
    headers: {
      ...(isWrite ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
    ...options,
  });

  // Handle 401 — clear tokens and redirect to login
  if (res.status === 401) {
    auth.clear();
    window.location.href = '/login';
    throw new Error('Unauthorized');
  }

  let data;
  try {
    data = await res.json();
  } catch {
    throw new Error(`HTTP ${res.status}: non-JSON response`);
  }

  if (!res.ok) {
    const message = data?.error?.message || `HTTP ${res.status}`;
    const err = new Error(message);
    err.status = res.status;
    err.data = data;
    throw err;
  }

  return data;
}

export function apiGet(path) {
  return apiFetch(path, { method: 'GET' });
}

export function apiPost(path, body) {
  return apiFetch(path, { method: 'POST', body: JSON.stringify(body) });
}
```

**Key changes from old client.js:**
- Removed `getCookie` / `X-CSRFToken` / `credentials: 'include'`
- Added `Authorization: Bearer <token>` from `auth.getToken()`
- 401 now clears tokens + hard redirects (instead of just throwing)
- Error detection: `!res.ok` + `data.error.message` (not `!data.ok` + `data.errors`)
- Returns flat `data` directly (no envelope)

---

## Section 3: Hooks

**`src/hooks/useFetch.js`:**

```js
import { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../api/client.js';

export function useFetch(path, deps = []) {
  const [data,       setData]       = useState(null);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState(null);
  const [pagination, setPagination] = useState(null);

  const fetch = useCallback(async () => {
    if (!path) { setLoading(false); return; }
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch(path, { method: 'GET' });
      setData(res);
      // Auto-extract pagination if embedded in flat response
      if (res && typeof res === 'object' && !Array.isArray(res) && 'page' in res) {
        setPagination({
          page: res.page,
          total_pages: res.total_pages,
          count: res.total,
          has_next: res.has_next,
          has_previous: res.has_previous,
        });
      } else {
        setPagination(null);
      }
    } catch (e) {
      if (e.message !== 'Unauthorized') {
        setError(e.message);
      }
      // 401 is already handled in apiFetch (clears + redirects)
    } finally {
      setLoading(false);
    }
  }, [path, ...deps]);

  useEffect(() => { fetch(); }, [fetch]);

  return { data, loading, error, pagination, refetch: fetch };
}
```

**`src/hooks/usePolling.js`:**

Change `setData(res.data)` → `setData(res)`. Remove 401 handling from hook (already handled in `apiFetch`).

```js
import { useState, useEffect, useRef, useCallback } from 'react';
import { apiFetch } from '../api/client.js';

export function usePolling(path, intervalMs = 3000) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const timerRef = useRef(null);

  const poll = useCallback(async () => {
    if (!path) return;
    try {
      const res = await apiFetch(path, { method: 'GET' });
      setData(res);
      setError(null);
    } catch (e) {
      if (e.message !== 'Unauthorized') {
        setError(e.message);
      }
    } finally {
      setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    poll();
    timerRef.current = setInterval(poll, intervalMs);
    return () => clearInterval(timerRef.current);
  }, [poll, intervalMs]);

  return { data, loading, error, refetch: poll };
}
```

---

## Section 4: LoginPage

After successful login, store both tokens:

```js
async function handleSubmit(e) {
  e.preventDefault();
  setError(null);
  setLoading(true);
  try {
    const res = await apiPost('/auth/login/', { username, password });
    auth.setTokens(res.access, res.refresh);
    navigate('/');
  } catch (err) {
    setError(err.data?.error?.message || err.message || 'Login failed');
  } finally {
    setLoading(false);
  }
}
```

**Note:** Error shape changed from `err.data?.detail` to `err.data?.error?.message`.

---

## Section 5: Logout (Layout.jsx)

Send refresh token in body to blacklist it, then clear storage:

```js
onClick={async () => {
  try {
    await apiPost('/auth/logout/', { refresh: auth.getRefresh() });
  } catch (_) {}
  auth.clear();
  navigate('/login');
}}
```

---

## Section 6: App.jsx Login Guard

Add before route matching:

```js
import { auth } from './auth.js';

// In App() component, before route matching:
if (path !== '/login' && !auth.isLoggedIn()) {
  navigate('/login');
  return null;
}
```

Handles first load with no token and manual localStorage clear. Mid-session expiry is handled by the 401 path in `apiFetch`.

---

## Section 7: ScansPage Data Shape Fix

The scans list API changed shape:
- Old: `res.data` = `[{...}, ...]` (plain array)
- New: `res` = `{results: [...], total, page, total_pages, has_next, has_previous}`

**In `ScansPage.jsx`:** replace any `data?.map(...)` with `data?.results?.map(...)` for the scans list.

All other pages are unaffected — their API response shapes are identical to the old `res.data` values.

---

## Out of Scope

- Token auto-refresh (silent refresh before expiry) — 401 → login redirect is sufficient for a self-hosted tool
- React Context for auth state — `auth.js` module is sufficient
- Any UI changes — login form appearance unchanged
