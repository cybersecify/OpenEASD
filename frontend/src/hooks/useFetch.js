import { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../api/client.js';

export function useFetch(path, deps = []) {
  const [data,       setData]       = useState(null);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState(null);
  const [pagination, setPagination] = useState(null);
  const [tick,       setTick]       = useState(0);

  const refetch = useCallback(() => setTick(t => t + 1), []);

  useEffect(() => {
    if (!path) { setLoading(false); return; }
    let ignore = false;
    setLoading(true);
    setError(null);
    (async () => {
      try {
        const res = await apiFetch(path, { method: 'GET' });
        if (ignore) return;
        setData(res);
        // Auto-extract pagination when embedded in flat response
        if (res && typeof res === 'object' && !Array.isArray(res) && 'page' in res && 'total_pages' in res && 'has_next' in res) {
          setPagination({
            page:         res.page,
            total_pages:  res.total_pages,
            count:        res.total,
            has_next:     res.has_next,
            has_previous: res.has_previous,
          });
        } else {
          setPagination(null);
        }
      } catch (e) {
        if (ignore) return;
        // 401 is handled in apiFetch (clears tokens + redirects) — don't set error for it
        if (e.status !== 401) setError(e.message);
      } finally {
        if (!ignore) setLoading(false);
      }
    })();
    return () => { ignore = true; };
  }, [path, tick, ...deps]); // eslint-disable-line react-hooks/exhaustive-deps

  return { data, loading, error, pagination, refetch };
}
