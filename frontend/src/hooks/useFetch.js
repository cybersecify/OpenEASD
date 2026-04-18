import { useState, useEffect, useCallback } from 'react';
import { apiFetch } from '../api/client.js';

export function useFetch(path, deps = []) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetch = useCallback(async () => {
    if (!path) return;
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch(path, { method: 'GET' });
      setData(res.data);
    } catch (e) {
      setError(e.message);
      if (e.status === 401) {
        window.location.href = '/login';
      }
    } finally {
      setLoading(false);
    }
  }, [path, ...deps]);

  useEffect(() => { fetch(); }, [fetch]);

  return { data, loading, error, refetch: fetch };
}
