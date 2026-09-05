import { describe, it, expect, beforeEach } from 'vitest';
import { auth } from './auth.js';

describe('auth token helpers', () => {
  beforeEach(() => localStorage.clear());

  it('starts logged out with null tokens', () => {
    expect(auth.getToken()).toBeNull();
    expect(auth.getRefresh()).toBeNull();
    expect(auth.isLoggedIn()).toBe(false);
  });

  it('setTokens stores both access and refresh', () => {
    auth.setTokens('access-1', 'refresh-1');
    expect(auth.getToken()).toBe('access-1');
    expect(auth.getRefresh()).toBe('refresh-1');
    expect(auth.isLoggedIn()).toBe(true);
  });

  it('clear removes both tokens and logs out', () => {
    auth.setTokens('a', 'r');
    auth.clear();
    expect(auth.getToken()).toBeNull();
    expect(auth.getRefresh()).toBeNull();
    expect(auth.isLoggedIn()).toBe(false);
  });

  it('isLoggedIn tracks only the access token', () => {
    // Refresh alone must not count as logged in — only a stored access token does.
    localStorage.setItem('openeasd_refresh', 'r');
    expect(auth.isLoggedIn()).toBe(false);
    auth.setTokens('a', 'r');
    expect(auth.isLoggedIn()).toBe(true);
  });
});
