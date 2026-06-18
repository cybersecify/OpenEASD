import axios from 'axios';
import { auth } from '../auth.js';
import { router } from '../router.jsx';

let _refreshPromise = null;

const axiosInstance = axios.create({ baseURL: '/api' });

axiosInstance.interceptors.request.use(config => {
  const token = auth.getToken();
  if (token) config.headers['Authorization'] = `Bearer ${token}`;
  return config;
});

axiosInstance.interceptors.response.use(
  response => response,
  async error => {
    const original = error.config;

    if (
      error.response?.status === 401 &&
      !original._retry &&
      original.url !== '/token/pair'
    ) {
      original._retry = true;

      if (!_refreshPromise) {
        _refreshPromise = (async () => {
          const refresh = auth.getRefresh();
          if (!refresh) return false;
          try {
            const res = await axios.post('/api/token/refresh', { refresh });
            auth.setTokens(res.data.access, refresh);
            return true;
          } catch {
            return false;
          }
        })().finally(() => { _refreshPromise = null; });
      }

      const refreshed = await _refreshPromise;
      if (refreshed) {
        original.headers['Authorization'] = `Bearer ${auth.getToken()}`;
        return axiosInstance(original);
      }

      auth.clear();
      router.navigate('/login', { replace: true });
      return Promise.reject(
        Object.assign(new Error('Unauthorized'), { status: 401 })
      );
    }

    const message =
      error.response?.data?.error?.message ||
      error.message ||
      `HTTP ${error.response?.status}`;
    return Promise.reject(
      Object.assign(new Error(message), {
        status: error.response?.status,
        data: error.response?.data,
      })
    );
  }
);

export default axiosInstance;
