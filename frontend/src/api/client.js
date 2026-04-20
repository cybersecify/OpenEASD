import { auth } from '../auth.js';

async function _tryRefresh() {
  const refresh = auth.getRefresh();
  if (!refresh) return false;
  try {
    const res = await fetch('/api/auth/refresh/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    auth.setTokens(data.access, refresh);
    return true;
  } catch {
    return false;
  }
}

async function _doFetch(path, options, token) {
  const isWrite = options.method && options.method !== 'GET' && options.method !== 'HEAD';
  return fetch(`/api${path}`, {
    headers: {
      ...(isWrite ? { 'Content-Type': 'application/json' } : {}),
      ...(token   ? { 'Authorization': `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
    ...options,
  });
}

export async function apiFetch(path, options = {}) {
  let res = await _doFetch(path, options, auth.getToken());

  // 401 on non-login path — try silent refresh once, then redirect
  if (res.status === 401 && path !== '/auth/login/') {
    const refreshed = await _tryRefresh();
    if (refreshed) {
      res = await _doFetch(path, options, auth.getToken());
    }
    if (res.status === 401) {
      auth.clear();
      window.location.replace('/login');
      throw Object.assign(new Error('Unauthorized'), { status: 401 });
    }
  }

  if (res.status === 401) {
    throw Object.assign(new Error('Unauthorized'), { status: 401 });
  }

  let data;
  try {
    data = await res.json();
  } catch {
    throw new Error(`HTTP ${res.status}: non-JSON response`);
  }

  if (!res.ok) {
    const message = data?.error?.message || `HTTP ${res.status}`;
    throw Object.assign(new Error(message), { status: res.status, data });
  }

  return data;
}

export function apiGet(path) {
  return apiFetch(path, { method: 'GET' });
}

export function apiPost(path, body) {
  return apiFetch(path, { method: 'POST', body: JSON.stringify(body) });
}
