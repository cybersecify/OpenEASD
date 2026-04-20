import { auth } from '../auth.js';

export async function apiFetch(path, options = {}) {
  const token  = auth.getToken();
  const isWrite = options.method && options.method !== 'GET' && options.method !== 'HEAD';

  const res = await fetch(`/api${path}`, {
    headers: {
      ...(isWrite ? { 'Content-Type': 'application/json' } : {}),
      ...(token    ? { 'Authorization': `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
    ...options,
  });

  // 401 — clear tokens and redirect; throw so callers can ignore
  if (res.status === 401) {
    auth.clear();
    window.location.href = '/login';
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
