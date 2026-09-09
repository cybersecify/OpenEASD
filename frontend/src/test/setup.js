// Vitest global setup: jest-dom matchers, DOM cleanup, and a localStorage
// polyfill. Neither happy-dom nor jsdom exposes a Storage global in this
// Vite 8 / Vitest 4 stack, so we back localStorage with a tiny in-memory
// store — the auth-token helpers only need get/set/remove/clear, and this
// keeps the tests deterministic and env-independent.
import '@testing-library/jest-dom';
import { afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';

if (typeof globalThis.localStorage === 'undefined') {
  const store = new Map();
  const localStoragePolyfill = {
    getItem: (k) => (store.has(String(k)) ? store.get(String(k)) : null),
    setItem: (k, v) => { store.set(String(k), String(v)); },
    removeItem: (k) => { store.delete(String(k)); },
    clear: () => { store.clear(); },
    key: (i) => Array.from(store.keys())[i] ?? null,
    get length() { return store.size; },
  };
  globalThis.localStorage = localStoragePolyfill;
  if (globalThis.window) globalThis.window.localStorage = localStoragePolyfill;
}

afterEach(() => {
  cleanup();
  localStorage.clear();
});
