import { useState, useEffect, useRef } from 'react';
import { apiFetch } from '../api/client.js';

const TERMINAL_STATUSES = new Set(['completed', 'failed', 'cancelled']);

export function usePolling(path, interval = 3000, enabled = true) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const timerRef = useRef(null);

  useEffect(() => {
    if (!path || !enabled) return;

    async function poll() {
      try {
        const res = await apiFetch(path, { method: 'GET' });
        setData(res.data);
        // Stop polling when scan reaches a terminal status
        const status = res.data?.session?.status;
        if (status && TERMINAL_STATUSES.has(status)) {
          clearInterval(timerRef.current);
        }
      } catch (e) {
        setError(e.message);
        clearInterval(timerRef.current);
      }
    }

    poll(); // immediate first call
    timerRef.current = setInterval(poll, interval);
    return () => clearInterval(timerRef.current);
  }, [path, interval, enabled]);

  return { data, error };
}
