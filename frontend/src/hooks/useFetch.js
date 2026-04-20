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
      // Auto-extract pagination when embedded in flat response
      if (res && typeof res === 'object' && !Array.isArray(res) && 'page' in res) {
        setPagination({
          page:        res.page,
          total_pages: res.total_pages,
          count:       res.total,
          has_next:    res.has_next,
          has_previous: res.has_previous,
        });
      } else {
        setPagination(null);
      }
    } catch (e) {
      // 401 is handled in apiFetch (clears tokens + redirects) — don't set error for it
      if (e.status !== 401) {
        setError(e.message);
      }
    } finally {
      setLoading(false);
    }
  }, [path, ...deps]);

  useEffect(() => { fetch(); }, [fetch]);

  return { data, loading, error, pagination, refetch: fetch };
}
