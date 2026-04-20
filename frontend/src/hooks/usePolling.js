import { useState, useEffect, useRef, useCallback } from 'react';
import { apiFetch } from '../api/client.js';

export function usePolling(path, intervalMs = 3000) {
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);
  const timerRef = useRef(null);

  const poll = useCallback(async () => {
    if (!path) return;
    try {
      const res = await apiFetch(path, { method: 'GET' });
      setData(res);
      setError(null);
    } catch (e) {
      // 401 handled in apiFetch — don't set error for it
      if (e.status !== 401) {
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
