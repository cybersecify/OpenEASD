import { describe, it, expect, beforeEach, vi } from 'vitest';
import axios from 'axios';

// router.jsx pulls the whole route tree (every page) — mock it so importing the
// axios instance stays cheap and we can assert redirect-to-login.
vi.mock('../router.jsx', () => ({ router: { navigate: vi.fn() } }));

import axiosInstance from './axiosInstance.js';
import { auth } from '../auth.js';
import { router } from '../router.jsx';

// Drive the instance's responses without real HTTP by swapping its adapter.
function onRequest(fn) {
  axiosInstance.defaults.adapter = fn;
}
function reject401(config, data = {}) {
  return Promise.reject(
    Object.assign(new Error('401'), {
      config,
      response: { status: 401, data },
      isAxiosError: true,
    })
  );
}
function ok(config, data = { ok: true }) {
  return { data, status: 200, statusText: 'OK', headers: {}, config };
}

beforeEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
  router.navigate.mockClear();
  axiosInstance.defaults.adapter = undefined;
});

describe('request interceptor', () => {
  it('attaches a Bearer header when a token is stored', async () => {
    auth.setTokens('ACCESS', 'REFRESH');
    let seen;
    onRequest(async (config) => {
      seen = config;
      return ok(config);
    });
    await axiosInstance.get('/dashboard');
    expect(seen.headers.Authorization).toBe('Bearer ACCESS');
  });

  it('sends no Authorization header when logged out', async () => {
    let seen;
    onRequest(async (config) => {
      seen = config;
      return ok(config);
    });
    await axiosInstance.get('/version');
    expect(seen.headers.Authorization).toBeUndefined();
  });
});

describe('401 response interceptor', () => {
  it('refreshes the token then retries the original request', async () => {
    auth.setTokens('OLD', 'REFRESH');
    const post = vi.spyOn(axios, 'post').mockResolvedValue({ data: { access: 'NEW' } });
    let calls = 0;
    onRequest(async (config) => {
      calls += 1;
      return calls === 1 ? reject401(config) : ok(config);
    });

    const res = await axiosInstance.get('/dashboard');

    expect(res.data.ok).toBe(true);
    expect(post).toHaveBeenCalledWith('/api/token/refresh', { refresh: 'REFRESH' });
    expect(auth.getToken()).toBe('NEW'); // new access token persisted
    expect(calls).toBe(2); // original + one retry
  });

  it('clears auth and redirects to /login when refresh fails', async () => {
    auth.setTokens('OLD', 'REFRESH');
    vi.spyOn(axios, 'post').mockRejectedValue(new Error('refresh rejected'));
    onRequest(async (config) => reject401(config));

    await expect(axiosInstance.get('/dashboard')).rejects.toMatchObject({ status: 401 });

    expect(auth.getToken()).toBeNull();
    expect(router.navigate).toHaveBeenCalledWith('/login', { replace: true });
  });

  it('does not attempt a refresh on a failed login (/token/pair)', async () => {
    const post = vi.spyOn(axios, 'post');
    onRequest(async (config) =>
      reject401(config, { error: { message: 'Invalid credentials' } })
    );

    await expect(axiosInstance.post('/token/pair', {})).rejects.toMatchObject({
      status: 401,
      message: 'Invalid credentials',
    });
    expect(post).not.toHaveBeenCalled(); // no refresh call
    expect(router.navigate).not.toHaveBeenCalled();
  });

  it('collapses concurrent 401s into a single refresh call', async () => {
    auth.setTokens('OLD', 'REFRESH');
    const post = vi.spyOn(axios, 'post').mockResolvedValue({ data: { access: 'NEW' } });
    onRequest(async (config) => (config._retry ? ok(config) : reject401(config)));

    await Promise.all([axiosInstance.get('/a'), axiosInstance.get('/b')]);

    expect(post).toHaveBeenCalledTimes(1); // shared _refreshPromise
  });
});
