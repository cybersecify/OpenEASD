function getCookie(name) {
  const match = document.cookie.match(new RegExp('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)'));
  return match ? decodeURIComponent(match[2]) : null;
}

export async function apiFetch(path, options = {}) {
  const csrf = getCookie('csrftoken');
  const res = await fetch(`/api${path}`, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(csrf ? { 'X-CSRFToken': csrf } : {}),
      ...(options.headers || {}),
    },
    ...options,
  });

  let data;
  try {
    data = await res.json();
  } catch {
    throw new Error(`HTTP ${res.status}: non-JSON response`);
  }

  if (!res.ok || !data.ok) {
    const err = new Error(
      typeof data.errors === 'string'
        ? data.errors
        : JSON.stringify(data.errors) || `HTTP ${res.status}`
    );
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
