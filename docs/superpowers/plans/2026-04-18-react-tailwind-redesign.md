# React + Tailwind Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace all inline-style React components with a production-quality dark-themed SPA using Tailwind CSS, a shared Layout sidebar, and fix two routing/auth bugs.

**Architecture:** Install Tailwind CSS v3 via npm with a custom semantic theme (brand/canvas/card/rim colours). Wrap all non-login pages in a shared `Layout` component with a fixed-width sidebar showing live badge counts. Convert each page to Tailwind utility classes, removing all JS-object inline styles and mouse-event handlers used only for visual state.

**Tech Stack:** React 18, Vite, Tailwind CSS v3, PostCSS, Autoprefixer, vanilla popstate router (no react-router)

---

### Task 1: Tailwind Setup

**Files:**
- Create: `frontend/tailwind.config.js`
- Create: `frontend/postcss.config.js`
- Create: `frontend/src/index.css`
- Modify: `frontend/package.json` (dev deps added by npm)
- Modify: `frontend/src/main.jsx`

- [ ] **Step 1: Install Tailwind and PostCSS**

```bash
cd frontend
npm install -D tailwindcss postcss autoprefixer
```

- [ ] **Step 2: Create `frontend/tailwind.config.js`**

```js
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        brand:  '#30c074',
        canvas: '#0d1117',
        card:   '#161b22',
        rim:    '#30363d',
        dim:    '#8b949e',
        lit:    '#e6edf3',
        body:   '#c9d1d9',
        hover:  '#1c2128',
      },
      fontFamily: {
        sans: ["'Segoe UI'", 'system-ui', '-apple-system', 'sans-serif'],
      },
    },
  },
  plugins: [],
};
```

- [ ] **Step 3: Create `frontend/postcss.config.js`**

```js
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};
```

- [ ] **Step 4: Create `frontend/src/index.css`**

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer components {
  /* Severity badges */
  .badge-critical { @apply bg-red-900/40 text-red-400 border border-red-800; }
  .badge-high     { @apply bg-orange-900/40 text-orange-400 border border-orange-800; }
  .badge-medium   { @apply bg-yellow-900/40 text-yellow-400 border border-yellow-800; }
  .badge-low      { @apply bg-blue-900/40 text-blue-400 border border-blue-800; }
  .badge-info     { @apply bg-gray-800/60 text-gray-400 border border-gray-700; }

  /* Finding status */
  .badge-open           { @apply bg-red-900/40 text-red-400 border border-red-800; }
  .badge-acknowledged   { @apply bg-yellow-900/40 text-yellow-400 border border-yellow-800; }
  .badge-fixed          { @apply bg-green-900/40 text-green-400 border border-green-800; }
  .badge-false_positive { @apply bg-gray-800/60 text-gray-400 border border-gray-700; }
  .badge-wont_fix       { @apply bg-gray-800/60 text-gray-400 border border-gray-700; }

  /* Scan status */
  .badge-pending   { @apply bg-gray-800/60 text-gray-400 border border-gray-700; }
  .badge-running   { @apply bg-blue-900/40 text-blue-400 border border-blue-800; }
  .badge-completed { @apply bg-green-900/40 text-green-400 border border-green-800; }
  .badge-failed    { @apply bg-red-900/40 text-red-400 border border-red-800; }
  .badge-cancelled { @apply bg-gray-800/60 text-gray-400 border border-gray-700; }
  .badge-scheduled { @apply bg-yellow-900/40 text-yellow-400 border border-yellow-800; }

  /* Generic / domain status */
  .badge-active   { @apply bg-green-900/40 text-green-400 border border-green-800; }
  .badge-inactive { @apply bg-gray-800/60 text-gray-400 border border-gray-700; }
  .badge-idle     { @apply bg-gray-800/60 text-gray-400 border border-gray-700; }
  .badge-web      { @apply bg-blue-900/40 text-blue-400 border border-blue-800; }

  /* Table */
  .tbl-th { @apply px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap border-b border-rim; }
  .tbl-td { @apply px-4 py-3 align-middle text-sm border-b border-rim/30; }

  /* Form inputs */
  .field { @apply w-full bg-canvas border border-rim rounded-md px-3 py-2 text-sm text-body placeholder-dim focus:outline-none focus:border-brand transition-colors; }

  /* Buttons */
  .btn-primary { @apply bg-brand text-canvas font-semibold text-sm px-4 py-2 rounded-md hover:opacity-90 disabled:opacity-50 disabled:cursor-default transition-opacity; }
  .btn-ghost   { @apply bg-transparent border border-rim text-body text-sm px-3 py-1.5 rounded-md hover:border-brand hover:text-brand transition-colors disabled:opacity-50 disabled:cursor-default; }
  .btn-danger  { @apply bg-transparent border border-rim text-body text-sm px-3 py-1.5 rounded-md hover:border-red-500 hover:text-red-400 transition-colors disabled:opacity-50 disabled:cursor-default; }
}
```

- [ ] **Step 5: Update `frontend/src/main.jsx`**

```jsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App.jsx';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
```

- [ ] **Step 6: Verify Tailwind builds**

```bash
cd frontend && npm run build
```

Expected: build succeeds, `dist/assets/*.css` is non-empty.

- [ ] **Step 7: Commit**

```bash
cd frontend && git add package.json package-lock.json tailwind.config.js postcss.config.js src/index.css src/main.jsx
cd .. && git commit -m "feat: add Tailwind CSS v3 + PostCSS, global stylesheet"
```

---

### Task 2: Shared Components

**Files:**
- Modify: `frontend/src/components/Badge.jsx`
- Modify: `frontend/src/components/Spinner.jsx`
- Modify: `frontend/src/components/Pagination.jsx`
- Modify: `frontend/src/components/ConfirmButton.jsx`
- Modify: `frontend/src/components/Notification.jsx`

- [ ] **Step 1: Rewrite `frontend/src/components/Badge.jsx`**

```jsx
import React from 'react';

export function Badge({ value }) {
  const label = value ?? '—';
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold capitalize badge-${label}`}>
      {label.replace('_', ' ')}
    </span>
  );
}
```

- [ ] **Step 2: Rewrite `frontend/src/components/Spinner.jsx`**

```jsx
import React from 'react';

export function Spinner({ size = 24 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      className="animate-spin text-brand" xmlns="http://www.w3.org/2000/svg">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
    </svg>
  );
}
```

- [ ] **Step 3: Read current `frontend/src/components/Pagination.jsx`** then rewrite:

```jsx
import React from 'react';

export function Pagination({ page, totalPages, onPage }) {
  if (!totalPages || totalPages <= 1) return null;
  return (
    <div className="flex items-center justify-center gap-2 py-2">
      <button onClick={() => onPage(page - 1)} disabled={page <= 1} className="btn-ghost">← Prev</button>
      <span className="text-sm text-dim">Page {page} of {totalPages}</span>
      <button onClick={() => onPage(page + 1)} disabled={page >= totalPages} className="btn-ghost">Next →</button>
    </div>
  );
}
```

- [ ] **Step 4: Read current `frontend/src/components/ConfirmButton.jsx`** then rewrite:

```jsx
import React, { useState } from 'react';

export function ConfirmButton({ label = 'Delete', confirmLabel = 'Confirm', onConfirm, disabled }) {
  const [confirming, setConfirming] = useState(false);
  if (confirming) {
    return (
      <span className="inline-flex gap-1.5 items-center">
        <button
          onClick={() => { setConfirming(false); onConfirm(); }}
          className="bg-transparent border border-red-600 text-red-400 text-xs px-2.5 py-1 rounded-md hover:bg-red-900/20 transition-colors"
        >
          {confirmLabel}
        </button>
        <button onClick={() => setConfirming(false)} className="btn-ghost text-xs px-2.5 py-1">Cancel</button>
      </span>
    );
  }
  return (
    <button disabled={disabled} onClick={() => setConfirming(true)} className="btn-danger">
      {label}
    </button>
  );
}
```

- [ ] **Step 5: Read current `frontend/src/components/Notification.jsx`** then rewrite:

```jsx
import React, { useEffect, useState } from 'react';

export function Notification({ message, type = 'success' }) {
  const [visible, setVisible] = useState(true);
  useEffect(() => {
    const t = setTimeout(() => setVisible(false), 4000);
    return () => clearTimeout(t);
  }, []);
  if (!visible) return null;
  const cls = type === 'error'
    ? 'bg-red-900/50 border-red-700 text-red-300'
    : 'bg-green-900/50 border-green-700 text-green-300';
  return (
    <div className={`fixed top-4 right-4 z-50 px-4 py-3 rounded-lg border text-sm font-medium shadow-lg ${cls}`}>
      {message}
    </div>
  );
}
```

- [ ] **Step 6: Build**

```bash
cd frontend && npm run build
```

- [ ] **Step 7: Commit**

```bash
git add frontend/src/components/ && git commit -m "feat: convert shared components to Tailwind"
```

---

### Task 3: Layout Component

**Files:**
- Create: `frontend/src/components/Layout.jsx`

- [ ] **Step 1: Create `frontend/src/components/Layout.jsx`**

```jsx
import React from 'react';
import { navigate } from '../App.jsx';
import { useFetch } from '../hooks/useFetch.js';

const NAV = [
  { label: 'Dashboard', path: '/' },
  { label: 'Domains',   path: '/domains' },
  { label: 'Scans',     path: '/scans' },
  { label: 'Findings',  path: '/findings' },
  { label: 'Workflows', path: '/workflows' },
  { label: 'Insights',  path: '/insights' },
];

function NavLink({ path, label, badge }) {
  const active = window.location.pathname === path ||
    (path !== '/' && window.location.pathname.startsWith(path));
  return (
    <button
      onClick={() => navigate(path)}
      className={`w-full text-left px-3 py-2 rounded-md text-sm font-medium flex items-center justify-between transition-colors
        ${active
          ? 'bg-brand/10 text-brand border border-brand/20'
          : 'text-dim hover:text-body hover:bg-hover'}`}
    >
      <span>{label}</span>
      {badge != null && badge > 0 && (
        <span className="text-xs bg-red-900/60 text-red-400 border border-red-800 rounded px-1.5 py-0.5 font-semibold">
          {badge}
        </span>
      )}
    </button>
  );
}

export function Layout({ children }) {
  const { data } = useFetch('/dashboard/');
  const criticalHigh = data ? (data.kpi_critical ?? 0) + (data.kpi_high ?? 0) : null;
  const running      = data ? (data.kpi_active_scans ?? 0) : null;

  return (
    <div className="flex min-h-screen bg-canvas font-sans">
      <aside className="w-56 shrink-0 bg-card border-r border-rim flex flex-col">
        <div className="px-4 py-4 border-b border-rim">
          <span className="text-brand font-bold text-base tracking-tight">OpenEASD</span>
        </div>
        <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
          {NAV.map(({ path, label }) => {
            const badge =
              label === 'Findings' ? criticalHigh :
              label === 'Scans'    ? running : null;
            return <NavLink key={path} path={path} label={label} badge={badge} />;
          })}
        </nav>
        <div className="px-3 py-3 border-t border-rim">
          <button
            onClick={() => navigate('/login')}
            className="w-full text-left px-3 py-2 rounded-md text-sm text-dim hover:text-body hover:bg-hover transition-colors"
          >
            Sign out
          </button>
        </div>
      </aside>
      <div className="flex-1 flex flex-col min-w-0">
        <main className="flex-1 p-6 overflow-auto">{children}</main>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Build**

```bash
cd frontend && npm run build
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/Layout.jsx && git commit -m "feat: add Layout component with sidebar and live badge counts"
```

---

### Task 4: Router + usePolling Bug Fixes

**Files:**
- Modify: `frontend/src/App.jsx`
- Modify: `frontend/src/hooks/usePolling.js`
- Create: `frontend/src/pages/ScanStartPage.jsx` (stub — replaced in Task 8)

- [ ] **Step 1: Read `frontend/src/App.jsx`**

Locate the two scan routing lines:

```js
if (path === '/scans') return <ScansPage />;
if (path.startsWith('/scans/') && path.length > 8) return <ScanDetailPage />;
```

- [ ] **Step 2: Update App.jsx — add ScanStartPage import and route**

Add import at the top with the other page imports:

```jsx
import ScanStartPage from './pages/ScanStartPage.jsx';
```

Add route between the two scan lines:

```jsx
if (path === '/scans') return <ScansPage />;
if (path === '/scans/start') return <ScanStartPage />;
if (path.startsWith('/scans/') && path.length > 8) return <ScanDetailPage />;
```

- [ ] **Step 3: Read `frontend/src/hooks/usePolling.js`**

- [ ] **Step 4: Fix 401 redirect in `frontend/src/hooks/usePolling.js`**

In the poll function's catch block, add the redirect (matching what `useFetch` already does):

Full replacement of the file:

```js
import { useState, useEffect, useRef, useCallback } from 'react';
import { apiFetch } from '../api/client.js';

export function usePolling(path, intervalMs = 3000) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const timerRef = useRef(null);

  const poll = useCallback(async () => {
    if (!path) return;
    try {
      const res = await apiFetch(path, { method: 'GET' });
      setData(res.data);
      setError(null);
    } catch (e) {
      setError(e.message);
      if (e.status === 401) {
        window.location.href = '/login';
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
```

- [ ] **Step 5: Create stub ScanStartPage so the build resolves the import**

```jsx
// frontend/src/pages/ScanStartPage.jsx  — temporary stub; replaced in Task 8
import React from 'react';
export default function ScanStartPage() { return <div>Start Scan</div>; }
```

- [ ] **Step 6: Build**

```bash
cd frontend && npm run build
```

- [ ] **Step 7: Commit**

```bash
git add frontend/src/App.jsx frontend/src/hooks/usePolling.js frontend/src/pages/ScanStartPage.jsx
git commit -m "fix: add /scans/start route; fix usePolling missing 401 redirect"
```

---

### Task 5: LoginPage

**Files:**
- Modify: `frontend/src/pages/LoginPage.jsx`

No Layout wrapper — login page has no sidebar.

- [ ] **Step 1: Rewrite `frontend/src/pages/LoginPage.jsx`**

```jsx
import React, { useState } from 'react';
import { apiPost } from '../api/client.js';
import { navigate } from '../App.jsx';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error,    setError]    = useState(null);
  const [loading,  setLoading]  = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await apiPost('/auth/login/', { username, password });
      navigate('/');
    } catch (err) {
      setError(err.data?.detail || err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-canvas flex items-center justify-center font-sans">
      <div className="w-full max-w-sm bg-card border border-rim rounded-xl p-8 shadow-xl">
        <h1 className="text-lit font-bold text-xl text-center mb-6">OpenEASD</h1>
        {error && (
          <div className="mb-4 px-3 py-2 rounded-md bg-red-900/40 border border-red-700 text-red-400 text-sm">
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs text-dim mb-1 font-medium">Username</label>
            <input type="text" value={username} onChange={e => setUsername(e.target.value)}
              autoComplete="username" required className="field" />
          </div>
          <div>
            <label className="block text-xs text-dim mb-1 font-medium">Password</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)}
              autoComplete="current-password" required className="field" />
          </div>
          <button type="submit" disabled={loading} className="btn-primary w-full mt-2">
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Build**

```bash
cd frontend && npm run build
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/LoginPage.jsx && git commit -m "feat: convert LoginPage to Tailwind"
```

---

### Task 6: DashboardPage

**Files:**
- Modify: `frontend/src/pages/DashboardPage.jsx`

- [ ] **Step 1: Rewrite `frontend/src/pages/DashboardPage.jsx`**

```jsx
import React from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { navigate } from '../App.jsx';
import { useFetch } from '../hooks/useFetch.js';

function KpiCard({ label, value, colorCls }) {
  return (
    <div className={`rounded-xl border p-5 text-center ${colorCls}`}>
      <div className="text-3xl font-bold leading-none mb-1">{value ?? 0}</div>
      <div className="text-xs font-semibold uppercase tracking-wider opacity-80">{label}</div>
    </div>
  );
}

function AssetCard({ label, value }) {
  return (
    <div className="bg-card border border-rim rounded-xl p-4 text-center">
      <div className="text-2xl font-bold text-lit">{value ?? 0}</div>
      <div className="text-xs text-dim mt-0.5">{label}</div>
    </div>
  );
}

export default function DashboardPage() {
  const { data, loading, error } = useFetch('/dashboard/');

  if (loading) return <Layout><div className="flex justify-center items-center h-64"><Spinner size={40} /></div></Layout>;
  if (error)   return <Layout><div className="text-red-400 p-4">Error: {error}</div></Layout>;
  if (!data)   return <Layout><div /></Layout>;

  const {
    kpi_domains = 0, kpi_active_scans = 0, kpi_critical = 0, kpi_high = 0,
    kpi_subdomains = 0, kpi_ips = 0, kpi_ports = 0, kpi_urls = 0,
    domain_status = [], urgent_findings = [],
  } = data;

  return (
    <Layout>
      <div className="space-y-6">
        <div>
          <h1 className="text-lit text-xl font-bold">Dashboard</h1>
          <p className="text-dim text-sm mt-0.5">Attack surface overview</p>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <KpiCard label="Domains"       value={kpi_domains}      colorCls="text-body border-rim bg-card" />
          <KpiCard label="Running Scans" value={kpi_active_scans}  colorCls="text-brand border-brand/30 bg-brand/10" />
          <KpiCard label="Critical Open" value={kpi_critical}      colorCls="text-red-400 border-red-800 bg-red-900/10" />
          <KpiCard label="High Open"     value={kpi_high}          colorCls="text-orange-400 border-orange-800 bg-orange-900/10" />
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <AssetCard label="Subdomains" value={kpi_subdomains} />
          <AssetCard label="IPs"        value={kpi_ips} />
          <AssetCard label="Ports"      value={kpi_ports} />
          <AssetCard label="URLs"       value={kpi_urls} />
        </div>

        <div className="bg-card border border-rim rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-rim">
            <h2 className="text-lit text-sm font-semibold">Domain Status</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr>{['Domain', 'Status', 'Last Scan', 'Critical', 'High', 'Actions'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr>
              </thead>
              <tbody>
                {domain_status.length === 0 ? (
                  <tr><td colSpan={6} className="tbl-td text-center text-dim py-8">No domains yet.</td></tr>
                ) : domain_status.map(d => (
                  <tr key={d.id} className="hover:bg-hover transition-colors">
                    <td className="tbl-td text-lit font-mono font-medium">{d.domain}</td>
                    <td className="tbl-td"><Badge value={d.scan_status || 'idle'} /></td>
                    <td className="tbl-td text-dim">{d.last_scan ? new Date(d.last_scan).toLocaleDateString() : '—'}</td>
                    <td className="tbl-td text-red-400 font-semibold">{d.critical ?? 0}</td>
                    <td className="tbl-td text-orange-400 font-semibold">{d.high ?? 0}</td>
                    <td className="tbl-td">
                      <button onClick={() => navigate('/scans?domain=' + d.domain)} className="btn-ghost">View Scans</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {urgent_findings.length > 0 && (
          <div className="bg-card border border-rim rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-rim">
              <h2 className="text-lit text-sm font-semibold">Urgent Findings</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr>{['Severity', 'Title', 'Domain', 'Source'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr>
                </thead>
                <tbody>
                  {urgent_findings.map(f => (
                    <tr key={f.id} className="hover:bg-hover transition-colors">
                      <td className="tbl-td"><Badge value={f.severity} /></td>
                      <td className="tbl-td text-body font-medium max-w-xs truncate">{f.title}</td>
                      <td className="tbl-td text-dim font-mono text-xs">{f.domain}</td>
                      <td className="tbl-td text-dim text-xs">{f.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Build**

```bash
cd frontend && npm run build
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/DashboardPage.jsx && git commit -m "feat: convert DashboardPage to Tailwind with Layout"
```

---

### Task 7: DomainsPage

**Files:**
- Modify: `frontend/src/pages/DomainsPage.jsx`

- [ ] **Step 1: Rewrite `frontend/src/pages/DomainsPage.jsx`**

```jsx
import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Notification } from '../components/Notification.jsx';
import { ConfirmButton } from '../components/ConfirmButton.jsx';
import { navigate } from '../App.jsx';
import { apiPost } from '../api/client.js';
import { useFetch } from '../hooks/useFetch.js';

function AddDomainForm({ onAdded }) {
  const [domain,  setDomain]  = useState('');
  const [saving,  setSaving]  = useState(false);
  const [err,     setErr]     = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!domain.trim()) { setErr('Domain is required.'); return; }
    setSaving(true); setErr(null);
    try {
      await apiPost('/domains/', { domain: domain.trim() });
      setDomain('');
      onAdded();
    } catch (e) {
      setErr(e.data?.detail || e.message || 'Failed to add domain.');
    } finally { setSaving(false); }
  }

  return (
    <div className="bg-card border border-rim rounded-xl p-5 mb-5">
      <h2 className="text-lit text-sm font-semibold mb-3">Add Domain</h2>
      <form onSubmit={handleSubmit} className="flex gap-3 flex-wrap">
        <input value={domain} onChange={e => setDomain(e.target.value)}
          placeholder="example.com" className="field flex-1 min-w-48" />
        <button type="submit" disabled={saving} className="btn-primary">
          {saving ? 'Adding…' : 'Add Domain'}
        </button>
      </form>
      {err && <p className="text-red-400 text-xs mt-2">{err}</p>}
    </div>
  );
}

export default function DomainsPage() {
  const { data, loading, error, refetch } = useFetch('/domains/');
  const [notification, setNotification] = useState(null);
  const [busyIds, setBusyIds] = useState(new Set());

  const domains = data || [];
  function notify(msg, type = 'success') { setNotification({ message: msg, type, key: Date.now() }); }
  function busy(id) { return busyIds.has(id); }
  function setBusy(id, val) {
    setBusyIds(s => { const ns = new Set(s); val ? ns.add(id) : ns.delete(id); return ns; });
  }

  async function handleToggle(id) {
    setBusy(id, true);
    try { await apiPost(`/domains/${id}/toggle/`); refetch(); }
    catch (e) { notify(e.message || 'Toggle failed.', 'error'); }
    finally { setBusy(id, false); }
  }

  async function handleDelete(id, domain) {
    setBusy(id, true);
    try { await apiPost(`/domains/${id}/delete/`); notify(`"${domain}" deleted.`); refetch(); }
    catch (e) { notify(e.message || 'Delete failed.', 'error'); }
    finally { setBusy(id, false); }
  }

  return (
    <Layout>
      {notification && <Notification key={notification.key} message={notification.message} type={notification.type} />}
      <div className="space-y-5">
        <div>
          <h1 className="text-lit text-xl font-bold">Domains</h1>
          <p className="text-dim text-sm mt-0.5">Manage monitored domains</p>
        </div>
        <AddDomainForm onAdded={() => { notify('Domain added.'); refetch(); }} />
        <div className="bg-card border border-rim rounded-xl overflow-hidden">
          {loading ? <div className="flex justify-center p-8"><Spinner /></div>
          : error   ? <div className="p-6 text-red-400 text-sm">Error: {error}</div>
          : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr>{['Domain', 'Active', 'Last Scan', 'Findings', 'Actions'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr>
                </thead>
                <tbody>
                  {domains.length === 0 ? (
                    <tr><td colSpan={5} className="tbl-td text-center text-dim py-10">No domains yet.</td></tr>
                  ) : domains.map(d => (
                    <tr key={d.id} className={`hover:bg-hover transition-colors ${busy(d.id) ? 'opacity-50' : ''}`}>
                      <td className="tbl-td text-lit font-mono font-medium">{d.domain}</td>
                      <td className="tbl-td"><Badge value={d.is_active ? 'active' : 'inactive'} /></td>
                      <td className="tbl-td text-dim">{d.last_scan_at ? new Date(d.last_scan_at).toLocaleDateString() : '—'}</td>
                      <td className="tbl-td text-dim">{d.finding_count ?? '—'}</td>
                      <td className="tbl-td">
                        <span className="inline-flex gap-1.5 items-center flex-wrap">
                          <button onClick={() => navigate(`/scans/start?domain=${d.domain}`)} className="btn-ghost">Scan</button>
                          <button onClick={() => navigate('/scans?domain=' + d.domain)} className="btn-ghost">History</button>
                          <button onClick={() => handleToggle(d.id)} disabled={busy(d.id)} className="btn-ghost">
                            {d.is_active ? 'Deactivate' : 'Activate'}
                          </button>
                          <ConfirmButton label="Delete" disabled={busy(d.id)} onConfirm={() => handleDelete(d.id, d.domain)} />
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Build**

```bash
cd frontend && npm run build
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/DomainsPage.jsx && git commit -m "feat: convert DomainsPage to Tailwind with Layout"
```

---

### Task 8: ScanStartPage (new)

**Files:**
- Modify: `frontend/src/pages/ScanStartPage.jsx` (replace stub from Task 4)

Reads `?domain=` from URL as default. Fetches `/api/domains/` and `/api/workflows/` for dropdowns. POSTs to `/api/scans/start/` then navigates to `/scans`.

- [ ] **Step 1: Rewrite `frontend/src/pages/ScanStartPage.jsx`**

```jsx
import React, { useState, useEffect } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { navigate } from '../App.jsx';
import { apiPost } from '../api/client.js';
import { useFetch } from '../hooks/useFetch.js';

export default function ScanStartPage() {
  const params     = new URLSearchParams(window.location.search);
  const initDomain = params.get('domain') || '';

  const { data: domainsData,   loading: ld } = useFetch('/domains/');
  const { data: workflowsData, loading: lw } = useFetch('/workflows/');

  const domains   = domainsData  || [];
  const workflows = workflowsData || [];
  const defaultWf = workflows.find(w => w.is_default);

  const [domain,     setDomain]    = useState(initDomain);
  const [workflowId, setWorkflow]  = useState('');
  const [scheduled,  setScheduled] = useState(false);
  const [schedTime,  setSchedTime] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error,      setError]     = useState(null);

  useEffect(() => {
    if (defaultWf && !workflowId) setWorkflow(String(defaultWf.id));
  }, [defaultWf]);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!domain) { setError('Select a domain.'); return; }
    setError(null); setSubmitting(true);
    try {
      const body = { domain };
      if (workflowId) body.workflow_id = Number(workflowId);
      if (scheduled && schedTime) body.scheduled_at = schedTime;
      await apiPost('/scans/start/', body);
      navigate('/scans');
    } catch (err) {
      setError(err.data?.detail || err.message || 'Failed to start scan.');
    } finally { setSubmitting(false); }
  }

  const loading = ld || lw;

  return (
    <Layout>
      <div className="max-w-lg space-y-5">
        <div>
          <h1 className="text-lit text-xl font-bold">Start Scan</h1>
          <p className="text-dim text-sm mt-0.5">Launch a new scan against a domain</p>
        </div>
        {loading ? <div className="flex justify-center p-8"><Spinner /></div> : (
          <div className="bg-card border border-rim rounded-xl p-6">
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs text-dim mb-1 font-medium">Domain *</label>
                <select value={domain} onChange={e => setDomain(e.target.value)} required className="field">
                  <option value="">— select domain —</option>
                  {domains.filter(d => d.is_active).map(d => (
                    <option key={d.id} value={d.domain}>{d.domain}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs text-dim mb-1 font-medium">Workflow</label>
                <select value={workflowId} onChange={e => setWorkflow(e.target.value)} className="field">
                  <option value="">— use default —</option>
                  {workflows.map(w => (
                    <option key={w.id} value={w.id}>{w.name}{w.is_default ? ' (default)' : ''}</option>
                  ))}
                </select>
              </div>
              <label className="inline-flex items-center gap-2 text-sm text-body cursor-pointer">
                <input type="checkbox" checked={scheduled} onChange={e => setScheduled(e.target.checked)} className="accent-brand" />
                Schedule for later
              </label>
              {scheduled && (
                <div>
                  <label className="block text-xs text-dim mb-1 font-medium">Scheduled time</label>
                  <input type="datetime-local" value={schedTime} onChange={e => setSchedTime(e.target.value)} className="field" />
                </div>
              )}
              {error && <p className="text-red-400 text-sm">{error}</p>}
              <div className="flex gap-3 pt-1">
                <button type="submit" disabled={submitting} className="btn-primary">
                  {submitting ? 'Starting…' : scheduled ? 'Schedule Scan' : 'Start Scan Now'}
                </button>
                <button type="button" onClick={() => navigate('/scans')} className="btn-ghost">Cancel</button>
              </div>
            </form>
          </div>
        )}
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Build**

```bash
cd frontend && npm run build
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/ScanStartPage.jsx && git commit -m "feat: implement ScanStartPage with domain/workflow selectors and schedule toggle"
```

---

### Task 9: ScansPage

**Files:**
- Modify: `frontend/src/pages/ScansPage.jsx`

Adds **Stop** button for running scans (was missing). POST `/api/scans/<uuid>/stop/`.

- [ ] **Step 1: Rewrite `frontend/src/pages/ScansPage.jsx`**

```jsx
import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Pagination } from '../components/Pagination.jsx';
import { ConfirmButton } from '../components/ConfirmButton.jsx';
import { Notification } from '../components/Notification.jsx';
import { navigate } from '../App.jsx';
import { apiPost } from '../api/client.js';
import { useFetch } from '../hooks/useFetch.js';

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export default function ScansPage() {
  const params = new URLSearchParams(window.location.search);
  const [domain,  setDomain]  = useState(params.get('domain') || '');
  const [status,  setStatus]  = useState('');
  const [page,    setPage]    = useState(1);
  const [notification, setNotification] = useState(null);
  const [busyIds, setBusyIds] = useState(new Set());

  const { data: domainsData } = useFetch('/domains/');
  const { data, loading, error, refetch } = useFetch(
    `/scans/?domain=${domain}&status=${status}&page=${page}`,
    [domain, status, page],
  );

  const scans      = data?.scans || data?.results || (Array.isArray(data) ? data : []);
  const pagination = data?.pagination || null;
  const scheduled  = data?.scheduled_jobs || [];
  const domains    = domainsData || [];

  function notify(msg, type = 'success') { setNotification({ message: msg, type, key: Date.now() }); }
  function busy(id) { return busyIds.has(id); }
  function setBusy(id, val) {
    setBusyIds(s => { const ns = new Set(s); val ? ns.add(id) : ns.delete(id); return ns; });
  }

  async function handleStop(uuid) {
    setBusy(uuid, true);
    try { await apiPost(`/scans/${uuid}/stop/`); notify('Scan stopped.'); refetch(); }
    catch (e) { notify(e.message || 'Stop failed.', 'error'); }
    finally { setBusy(uuid, false); }
  }

  async function handleDelete(uuid) {
    setBusy(uuid, true);
    try { await apiPost(`/scans/${uuid}/delete/`); notify('Scan deleted.'); refetch(); }
    catch (e) { notify(e.message || 'Delete failed.', 'error'); }
    finally { setBusy(uuid, false); }
  }

  async function handleCancelJob(jobId) {
    try { await apiPost(`/scheduled/${jobId}/cancel/`); notify('Job cancelled.'); refetch(); }
    catch (e) { notify(e.message || 'Cancel failed.', 'error'); }
  }

  return (
    <Layout>
      {notification && <Notification key={notification.key} message={notification.message} type={notification.type} />}
      <div className="space-y-5">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h1 className="text-lit text-xl font-bold">Scans</h1>
            <p className="text-dim text-sm mt-0.5">Scan history and scheduled jobs</p>
          </div>
          <button onClick={() => navigate('/scans/start')} className="btn-primary">+ New Scan</button>
        </div>

        {/* Filters */}
        <div className="flex gap-3 flex-wrap">
          <select value={domain} onChange={e => { setDomain(e.target.value); setPage(1); }} className="field w-52">
            <option value="">All domains</option>
            {domains.map(d => <option key={d.id} value={d.domain}>{d.domain}</option>)}
          </select>
          <select value={status} onChange={e => { setStatus(e.target.value); setPage(1); }} className="field w-40">
            <option value="">All statuses</option>
            {['pending', 'running', 'completed', 'failed', 'cancelled'].map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>

        {/* Scans table */}
        <div className="bg-card border border-rim rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-rim">
            <h2 className="text-lit text-sm font-semibold">Scan Sessions</h2>
          </div>
          {loading ? <div className="flex justify-center p-8"><Spinner /></div>
          : error   ? <div className="p-6 text-red-400 text-sm">Error: {error}</div>
          : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-sm">
                  <thead>
                    <tr>{['Domain', 'Status', 'Started', 'Findings', 'Actions'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr>
                  </thead>
                  <tbody>
                    {scans.length === 0 ? (
                      <tr><td colSpan={5} className="tbl-td text-center text-dim py-10">No scans yet.</td></tr>
                    ) : scans.map(s => {
                      const id = s.uuid || s.id;
                      return (
                        <tr key={id} className={`hover:bg-hover transition-colors ${busy(id) ? 'opacity-50' : ''}`}>
                          <td className="tbl-td text-lit font-mono font-medium">{s.domain || '—'}</td>
                          <td className="tbl-td"><Badge value={s.status} /></td>
                          <td className="tbl-td text-dim">{fmtDate(s.started_at || s.created_at)}</td>
                          <td className="tbl-td text-body">{s.finding_count ?? '—'}</td>
                          <td className="tbl-td">
                            <span className="inline-flex gap-1.5 items-center flex-wrap">
                              <button onClick={() => navigate(`/scans/${id}`)} className="btn-ghost">View</button>
                              {s.status === 'running' && (
                                <ConfirmButton label="Stop" confirmLabel="Stop scan?" onConfirm={() => handleStop(id)} disabled={busy(id)} />
                              )}
                              {['completed', 'failed', 'cancelled'].includes(s.status) && (
                                <ConfirmButton label="Delete" onConfirm={() => handleDelete(id)} disabled={busy(id)} />
                              )}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              {pagination && (
                <div className="px-4 py-3 border-t border-rim">
                  <Pagination page={pagination.page} totalPages={pagination.total_pages} onPage={setPage} />
                </div>
              )}
            </>
          )}
        </div>

        {/* Scheduled jobs */}
        {scheduled.length > 0 && (
          <div className="bg-card border border-rim rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-rim">
              <h2 className="text-lit text-sm font-semibold">Scheduled Jobs</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr>{['Domain', 'Scheduled At', 'Actions'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr>
                </thead>
                <tbody>
                  {scheduled.map(j => (
                    <tr key={j.id} className="hover:bg-hover transition-colors">
                      <td className="tbl-td font-mono text-lit">{j.domain || j.name || '—'}</td>
                      <td className="tbl-td text-dim">{fmtDate(j.next_run_time || j.scheduled_at)}</td>
                      <td className="tbl-td">
                        <ConfirmButton label="Cancel" confirmLabel="Cancel job?" onConfirm={() => handleCancelJob(j.id)} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Build**

```bash
cd frontend && npm run build
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/ScansPage.jsx && git commit -m "feat: convert ScansPage to Tailwind with Layout; add Stop button for running scans"
```

---

### Task 10: ScanDetailPage

**Files:**
- Modify: `frontend/src/pages/ScanDetailPage.jsx`

Uses `usePolling` for live status (3s), `useFetch` for full detail. Has tabs: subdomains / ips / ports / urls / findings.

- [ ] **Step 1: Rewrite `frontend/src/pages/ScanDetailPage.jsx`**

```jsx
import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { ConfirmButton } from '../components/ConfirmButton.jsx';
import { Notification } from '../components/Notification.jsx';
import { Pagination } from '../components/Pagination.jsx';
import { navigate } from '../App.jsx';
import { apiPost } from '../api/client.js';
import { useFetch } from '../hooks/useFetch.js';
import { usePolling } from '../hooks/usePolling.js';

const TABS = ['subdomains', 'ips', 'ports', 'urls', 'findings'];
const PAGE_SIZE = 50;

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function StatCard({ label, value, danger }) {
  return (
    <div className={`border rounded-lg px-4 py-3 text-center ${danger ? 'border-red-800 bg-red-900/10' : 'border-rim bg-card'}`}>
      <div className={`text-xl font-bold ${danger ? 'text-red-400' : 'text-lit'}`}>{value ?? 0}</div>
      <div className="text-xs text-dim mt-0.5">{label}</div>
    </div>
  );
}

export default function ScanDetailPage() {
  const uuid = window.location.pathname.split('/scans/')[1]?.replace(/\/$/, '');
  const [tab,  setTab]  = useState('subdomains');
  const [page, setPage] = useState(1);
  const [notification, setNotification] = useState(null);
  const [busy, setBusy] = useState(false);

  const { data: statusData } = usePolling(uuid ? `/scans/${uuid}/status/` : null, 3000);
  const { data, loading, error, refetch } = useFetch(uuid ? `/scans/${uuid}/` : null, [uuid]);

  function notify(msg, type = 'success') { setNotification({ message: msg, type, key: Date.now() }); }

  async function handleStop() {
    setBusy(true);
    try { await apiPost(`/scans/${uuid}/stop/`); notify('Scan stopped.'); refetch(); }
    catch (e) { notify(e.message || 'Stop failed.', 'error'); }
    finally { setBusy(false); }
  }

  async function handleDelete() {
    setBusy(true);
    try { await apiPost(`/scans/${uuid}/delete/`); navigate('/scans'); }
    catch (e) { notify(e.message || 'Delete failed.', 'error'); setBusy(false); }
  }

  if (loading) return <Layout><div className="flex justify-center items-center h-64"><Spinner size={40} /></div></Layout>;
  if (error)   return <Layout><div className="text-red-400 p-4">Error: {error}</div></Layout>;
  if (!data)   return <Layout><div /></Layout>;

  const currentStatus = statusData?.status || data.status;
  const isRunning = currentStatus === 'running';

  const {
    domain, started_at, finished_at, workflow_name,
    subdomain_count = 0, ip_count = 0, port_count = 0, url_count = 0,
    critical_count = 0, finding_count = 0,
    subdomains = [], ips = [], ports = [], urls = [], findings = [],
  } = data;

  const tabData   = { subdomains, ips, ports, urls, findings };
  const items     = tabData[tab] || [];
  const paged     = items.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const totalPages = Math.ceil(items.length / PAGE_SIZE);

  return (
    <Layout>
      {notification && <Notification key={notification.key} message={notification.message} type={notification.type} />}
      <div className="space-y-5">

        {/* Header */}
        <div className="flex items-start justify-between flex-wrap gap-3">
          <div>
            <button onClick={() => navigate('/scans')} className="text-dim text-xs hover:text-body mb-1 block">← Scans</button>
            <h1 className="text-lit text-xl font-bold font-mono">{domain}</h1>
            <div className="flex items-center gap-2 mt-1 flex-wrap">
              <Badge value={currentStatus} />
              {workflow_name && <span className="text-xs text-dim">{workflow_name}</span>}
              {isRunning && <Spinner size={14} />}
            </div>
            <p className="text-dim text-xs mt-1">
              Started: {fmtDate(started_at)}{finished_at && <> · Finished: {fmtDate(finished_at)}</>}
            </p>
          </div>
          <span className="inline-flex gap-1.5 items-center">
            {isRunning && <ConfirmButton label="Stop" confirmLabel="Stop scan?" onConfirm={handleStop} disabled={busy} />}
            <ConfirmButton label="Delete" onConfirm={handleDelete} disabled={busy} />
          </span>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
          <StatCard label="Subdomains" value={subdomain_count} />
          <StatCard label="IPs"        value={ip_count} />
          <StatCard label="Ports"      value={port_count} />
          <StatCard label="URLs"       value={url_count} />
          <StatCard label="Critical"   value={critical_count} danger />
          <StatCard label="Findings"   value={finding_count} />
        </div>

        {/* Tabs */}
        <div>
          <div className="flex gap-0.5 border-b border-rim mb-4">
            {TABS.map(t => (
              <button key={t} onClick={() => { setTab(t); setPage(1); }}
                className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors capitalize
                  ${t === tab ? 'border-brand text-brand' : 'border-transparent text-dim hover:text-body'}`}>
                {t} ({(tabData[t] || []).length})
              </button>
            ))}
          </div>

          <div className="bg-card border border-rim rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                {tab === 'subdomains' && <>
                  <thead><tr>{['Subdomain', 'Active', 'IPs'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr></thead>
                  <tbody>
                    {paged.length === 0
                      ? <tr><td colSpan={3} className="tbl-td text-center text-dim py-8">None found.</td></tr>
                      : paged.map((s, i) => (
                        <tr key={i} className="hover:bg-hover">
                          <td className="tbl-td font-mono text-lit">{s.subdomain || s.hostname || s}</td>
                          <td className="tbl-td"><Badge value={s.is_active ? 'active' : 'inactive'} /></td>
                          <td className="tbl-td text-dim text-xs">{(s.ips || []).join(', ') || '—'}</td>
                        </tr>
                      ))}
                  </tbody>
                </>}
                {tab === 'ips' && <>
                  <thead><tr>{['IP', 'PTR'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr></thead>
                  <tbody>
                    {paged.length === 0
                      ? <tr><td colSpan={2} className="tbl-td text-center text-dim py-8">None found.</td></tr>
                      : paged.map((ip, i) => (
                        <tr key={i} className="hover:bg-hover">
                          <td className="tbl-td font-mono text-lit">{ip.ip || ip}</td>
                          <td className="tbl-td text-dim text-xs font-mono">{ip.ptr || '—'}</td>
                        </tr>
                      ))}
                  </tbody>
                </>}
                {tab === 'ports' && <>
                  <thead><tr>{['Host', 'Port', 'Service', 'Web?'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr></thead>
                  <tbody>
                    {paged.length === 0
                      ? <tr><td colSpan={4} className="tbl-td text-center text-dim py-8">None found.</td></tr>
                      : paged.map((p, i) => (
                        <tr key={i} className="hover:bg-hover">
                          <td className="tbl-td font-mono text-dim text-xs">{p.ip || '—'}</td>
                          <td className="tbl-td font-mono text-lit font-semibold">{p.port}</td>
                          <td className="tbl-td text-dim">{p.service || '—'}</td>
                          <td className="tbl-td">{p.is_web ? <Badge value="web" /> : <span className="text-dim">—</span>}</td>
                        </tr>
                      ))}
                  </tbody>
                </>}
                {tab === 'urls' && <>
                  <thead><tr>{['URL', 'Status', 'Title'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr></thead>
                  <tbody>
                    {paged.length === 0
                      ? <tr><td colSpan={3} className="tbl-td text-center text-dim py-8">None found.</td></tr>
                      : paged.map((u, i) => (
                        <tr key={i} className="hover:bg-hover">
                          <td className="tbl-td font-mono text-brand text-xs max-w-xs truncate">
                            <a href={u.url || u} target="_blank" rel="noopener noreferrer" className="hover:underline">{u.url || u}</a>
                          </td>
                          <td className="tbl-td text-dim">{u.status_code || '—'}</td>
                          <td className="tbl-td text-body text-xs max-w-xs truncate">{u.title || '—'}</td>
                        </tr>
                      ))}
                  </tbody>
                </>}
                {tab === 'findings' && <>
                  <thead><tr>{['Sev', 'Title', 'Target', 'Source'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr></thead>
                  <tbody>
                    {paged.length === 0
                      ? <tr><td colSpan={4} className="tbl-td text-center text-dim py-8">None found.</td></tr>
                      : paged.map((f, i) => (
                        <tr key={i} className="hover:bg-hover">
                          <td className="tbl-td"><Badge value={f.severity} /></td>
                          <td className="tbl-td text-body font-medium max-w-xs truncate">{f.title}</td>
                          <td className="tbl-td font-mono text-dim text-xs">{f.target}</td>
                          <td className="tbl-td text-dim text-xs">{f.source}</td>
                        </tr>
                      ))}
                  </tbody>
                </>}
              </table>
            </div>
            {totalPages > 1 && (
              <div className="px-4 py-3 border-t border-rim">
                <Pagination page={page} totalPages={totalPages} onPage={setPage} />
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Build**

```bash
cd frontend && npm run build
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/ScanDetailPage.jsx && git commit -m "feat: convert ScanDetailPage to Tailwind with Layout"
```

---

### Task 11: FindingsPage

**Files:**
- Modify: `frontend/src/pages/FindingsPage.jsx`

- [ ] **Step 1: Rewrite `frontend/src/pages/FindingsPage.jsx`**

```jsx
import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Pagination } from '../components/Pagination.jsx';
import { Notification } from '../components/Notification.jsx';
import { apiPost } from '../api/client.js';
import { useFetch } from '../hooks/useFetch.js';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES   = ['open', 'acknowledged', 'fixed', 'false_positive', 'wont_fix'];

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function StatusEditor({ findingId, current, onUpdated }) {
  const [editing, setEditing] = useState(false);
  const [saving,  setSaving]  = useState(false);

  async function handleChange(e) {
    const val = e.target.value;
    setSaving(true);
    try {
      await apiPost(`/scans/findings/${findingId}/status/`, { status: val });
      onUpdated(findingId, val);
    } finally { setSaving(false); setEditing(false); }
  }

  if (editing) {
    return (
      <select autoFocus defaultValue={current} onChange={handleChange}
        disabled={saving} className="field text-xs py-0.5 px-1 w-36">
        {STATUSES.map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
      </select>
    );
  }
  return (
    <button onClick={() => setEditing(true)} className="text-left">
      <Badge value={current} />
    </button>
  );
}

export default function FindingsPage() {
  const params = new URLSearchParams(window.location.search);
  const [severity, setSeverity] = useState(params.get('severity') || '');
  const [status,   setStatus]   = useState('open');
  const [domain,   setDomain]   = useState(params.get('domain') || '');
  const [page,     setPage]     = useState(1);
  const [notification, setNotification] = useState(null);

  const { data: domainsData } = useFetch('/domains/');
  const { data, loading, error, refetch } = useFetch(
    `/scans/findings/?severity=${severity}&status=${status}&domain=${domain}&page=${page}`,
    [severity, status, domain, page],
  );

  const findings   = data?.findings || data?.results || (Array.isArray(data) ? data : []);
  const pagination = data?.pagination || null;
  const domains    = domainsData || [];

  function notify(msg, type = 'success') { setNotification({ message: msg, type, key: Date.now() }); }

  return (
    <Layout>
      {notification && <Notification key={notification.key} message={notification.message} type={notification.type} />}
      <div className="space-y-5">
        <div>
          <h1 className="text-lit text-xl font-bold">Findings</h1>
          <p className="text-dim text-sm mt-0.5">All findings across all scans</p>
        </div>

        {/* Filters */}
        <div className="flex gap-3 flex-wrap">
          <select value={severity} onChange={e => { setSeverity(e.target.value); setPage(1); }} className="field w-36">
            <option value="">All severities</option>
            {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={status} onChange={e => { setStatus(e.target.value); setPage(1); }} className="field w-40">
            <option value="">All statuses</option>
            {STATUSES.map(s => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
          </select>
          <select value={domain} onChange={e => { setDomain(e.target.value); setPage(1); }} className="field w-52">
            <option value="">All domains</option>
            {domains.map(d => <option key={d.id} value={d.domain}>{d.domain}</option>)}
          </select>
        </div>

        <div className="bg-card border border-rim rounded-xl overflow-hidden">
          {loading ? <div className="flex justify-center p-8"><Spinner /></div>
          : error   ? <div className="p-6 text-red-400 text-sm">Error: {error}</div>
          : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-sm">
                  <thead>
                    <tr>{['Severity', 'Title', 'Target', 'Source', 'Status', 'Found'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr>
                  </thead>
                  <tbody>
                    {findings.length === 0 ? (
                      <tr><td colSpan={6} className="tbl-td text-center text-dim py-10">No findings.</td></tr>
                    ) : findings.map(f => (
                      <tr key={f.id} className="hover:bg-hover transition-colors">
                        <td className="tbl-td"><Badge value={f.severity} /></td>
                        <td className="tbl-td text-body font-medium max-w-xs truncate">{f.title}</td>
                        <td className="tbl-td font-mono text-dim text-xs">{f.target}</td>
                        <td className="tbl-td text-dim text-xs">{f.source}</td>
                        <td className="tbl-td">
                          <StatusEditor findingId={f.id} current={f.status || 'open'}
                            onUpdated={() => { notify('Status updated.'); refetch(); }} />
                        </td>
                        <td className="tbl-td text-dim text-xs">{fmtDate(f.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {pagination && (
                <div className="px-4 py-3 border-t border-rim">
                  <Pagination page={pagination.page} totalPages={pagination.total_pages} onPage={setPage} />
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Build**

```bash
cd frontend && npm run build
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/FindingsPage.jsx && git commit -m "feat: convert FindingsPage to Tailwind with Layout"
```

---

### Task 12: WorkflowsPage

**Files:**
- Modify: `frontend/src/pages/WorkflowsPage.jsx`

- [ ] **Step 1: Rewrite `frontend/src/pages/WorkflowsPage.jsx`**

```jsx
import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { ConfirmButton } from '../components/ConfirmButton.jsx';
import { Notification } from '../components/Notification.jsx';
import { navigate } from '../App.jsx';
import { apiPost } from '../api/client.js';
import { useFetch } from '../hooks/useFetch.js';

function CreateWorkflowForm({ onCreated }) {
  const [name,     setName]    = useState('');
  const [desc,     setDesc]    = useState('');
  const [isDef,    setDef]     = useState(false);
  const [selected, setSel]     = useState([]);
  const [saving,   setSaving]  = useState(false);
  const [err,      setErr]     = useState(null);

  const { data: toolsData } = useFetch('/workflows/tools/');
  const allTools = toolsData?.tools || [];

  function toggleTool(key) {
    setSel(prev => prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]);
  }

  async function handleSubmit(e) {
    e.preventDefault();
    if (!name.trim()) { setErr('Name is required.'); return; }
    setSaving(true); setErr(null);
    try {
      const res = await apiPost('/workflows/create/', {
        name: name.trim(), description: desc.trim(), is_default: isDef, tools: selected,
      });
      onCreated(res.data);
      setName(''); setDesc(''); setDef(false); setSel([]);
    } catch (e) { setErr(e.message); }
    finally { setSaving(false); }
  }

  return (
    <div className="bg-card border border-rim rounded-xl p-5 mb-5">
      <h2 className="text-lit text-sm font-semibold mb-4">Create Workflow</h2>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label className="block text-xs text-dim mb-1">Name *</label>
            <input value={name} onChange={e => setName(e.target.value)} placeholder="Workflow name" className="field" />
          </div>
          <div>
            <label className="block text-xs text-dim mb-1">Description</label>
            <input value={desc} onChange={e => setDesc(e.target.value)} placeholder="Optional" className="field" />
          </div>
        </div>
        <label className="inline-flex items-center gap-2 text-sm text-body cursor-pointer">
          <input type="checkbox" checked={isDef} onChange={e => setDef(e.target.checked)} className="accent-brand" />
          Set as default
        </label>
        {allTools.length > 0 && (
          <div>
            <p className="text-xs text-dim mb-2">Tools</p>
            <div className="flex flex-wrap gap-2">
              {allTools.map(tool => (
                <label key={tool.key}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs cursor-pointer border transition-colors
                    ${selected.includes(tool.key)
                      ? 'bg-brand/10 border-brand/40 text-brand'
                      : 'bg-canvas border-rim text-body hover:border-dim'}`}>
                  <input type="checkbox" className="hidden" checked={selected.includes(tool.key)} onChange={() => toggleTool(tool.key)} />
                  {tool.label || tool.key}
                </label>
              ))}
            </div>
          </div>
        )}
        {err && <p className="text-red-400 text-xs">{err}</p>}
        <button type="submit" disabled={saving} className="btn-primary">{saving ? 'Creating…' : 'Create Workflow'}</button>
      </form>
    </div>
  );
}

export default function WorkflowsPage() {
  const { data, loading, error, refetch } = useFetch('/workflows/');
  const [notification, setNotification] = useState(null);
  const [busyIds, setBusyIds] = useState(new Set());

  const workflows = data || [];
  function notify(msg, type = 'success') { setNotification({ message: msg, type, key: Date.now() }); }
  function busy(id) { return busyIds.has(id); }
  function setBusy(id, val) {
    setBusyIds(s => { const ns = new Set(s); val ? ns.add(id) : ns.delete(id); return ns; });
  }

  async function handleDelete(id, name) {
    setBusy(id, true);
    try { await apiPost(`/workflows/${id}/delete/`); notify(`"${name}" deleted.`); refetch(); }
    catch (e) { notify(e.message || 'Delete failed.', 'error'); }
    finally { setBusy(id, false); }
  }

  return (
    <Layout>
      {notification && <Notification key={notification.key} message={notification.message} type={notification.type} />}
      <div className="space-y-5">
        <div>
          <h1 className="text-lit text-xl font-bold">Workflows</h1>
          <p className="text-dim text-sm mt-0.5">Manage scan workflows and tool configurations</p>
        </div>
        <CreateWorkflowForm onCreated={() => { notify('Workflow created.'); refetch(); }} />
        <div className="bg-card border border-rim rounded-xl overflow-hidden">
          {loading ? <div className="flex justify-center p-8"><Spinner /></div>
          : error   ? <div className="p-6 text-red-400 text-sm">Error: {error}</div>
          : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr>{['Name', 'Default?', 'Tools', 'Description', 'Actions'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr>
                </thead>
                <tbody>
                  {workflows.length === 0 ? (
                    <tr><td colSpan={5} className="tbl-td text-center text-dim py-10">No workflows yet.</td></tr>
                  ) : workflows.map(wf => (
                    <tr key={wf.id} className={`hover:bg-hover transition-colors ${busy(wf.id) ? 'opacity-50' : ''}`}>
                      <td className="tbl-td text-lit font-medium">{wf.name}</td>
                      <td className="tbl-td">
                        {wf.is_default
                          ? <span className="text-brand text-xs font-semibold">Default</span>
                          : <span className="text-dim text-xs">—</span>}
                      </td>
                      <td className="tbl-td text-dim">{wf.steps ? wf.steps.filter(s => s.enabled !== false).length : '—'}</td>
                      <td className="tbl-td text-dim max-w-xs truncate">{wf.description || '—'}</td>
                      <td className="tbl-td">
                        <span className="inline-flex gap-1.5 items-center">
                          <button onClick={() => navigate(`/workflows/${wf.id}`)} className="btn-ghost">View</button>
                          <ConfirmButton label="Delete" disabled={busy(wf.id)} onConfirm={() => handleDelete(wf.id, wf.name)} />
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Build**

```bash
cd frontend && npm run build
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/WorkflowsPage.jsx && git commit -m "feat: convert WorkflowsPage to Tailwind with Layout"
```

---

### Task 13: WorkflowDetailPage

**Files:**
- Modify: `frontend/src/pages/WorkflowDetailPage.jsx`

- [ ] **Step 1: Rewrite `frontend/src/pages/WorkflowDetailPage.jsx`**

```jsx
import React, { useState, useEffect } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Notification } from '../components/Notification.jsx';
import { navigate } from '../App.jsx';
import { apiPost } from '../api/client.js';
import { useFetch } from '../hooks/useFetch.js';

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export default function WorkflowDetailPage() {
  const id = window.location.pathname.split('/workflows/')[1]?.replace(/\/$/, '');
  const { data, loading, error, refetch } = useFetch(id ? `/workflows/${id}/` : null, [id]);
  const [notification, setNotification] = useState(null);
  const [name,  setName]  = useState('');
  const [desc,  setDesc]  = useState('');
  const [saving, setSaving] = useState(false);
  const [toggling, setToggling] = useState(null);

  useEffect(() => {
    if (data) { setName(data.name || ''); setDesc(data.description || ''); }
  }, [data]);

  function notify(msg, type = 'success') { setNotification({ message: msg, type, key: Date.now() }); }

  async function handleSave(e) {
    e.preventDefault(); setSaving(true);
    try { await apiPost(`/workflows/${id}/update/`, { name: name.trim(), description: desc.trim() }); notify('Updated.'); refetch(); }
    catch (e) { notify(e.message || 'Update failed.', 'error'); }
    finally { setSaving(false); }
  }

  async function handleToggle(tool) {
    setToggling(tool);
    try { await apiPost(`/workflows/${id}/steps/${tool}/toggle/`); refetch(); }
    catch (e) { notify(e.message || 'Toggle failed.', 'error'); }
    finally { setToggling(null); }
  }

  if (loading) return <Layout><div className="flex justify-center items-center h-64"><Spinner size={40} /></div></Layout>;
  if (error)   return <Layout><div className="text-red-400 p-4">Error: {error}</div></Layout>;
  if (!data)   return <Layout><div /></Layout>;

  const { steps = [], recent_runs = [], is_default } = data;

  return (
    <Layout>
      {notification && <Notification key={notification.key} message={notification.message} type={notification.type} />}
      <div className="space-y-6 max-w-3xl">
        <div>
          <button onClick={() => navigate('/workflows')} className="text-dim text-xs hover:text-body mb-1 block">← Workflows</button>
          <h1 className="text-lit text-xl font-bold">{data.name}</h1>
          {is_default && <span className="text-brand text-xs font-semibold">Default workflow</span>}
        </div>

        {/* Edit form */}
        <div className="bg-card border border-rim rounded-xl p-5">
          <h2 className="text-lit text-sm font-semibold mb-4">Edit</h2>
          <form onSubmit={handleSave} className="space-y-3">
            <div>
              <label className="block text-xs text-dim mb-1">Name</label>
              <input value={name} onChange={e => setName(e.target.value)} className="field" />
            </div>
            <div>
              <label className="block text-xs text-dim mb-1">Description</label>
              <input value={desc} onChange={e => setDesc(e.target.value)} className="field" />
            </div>
            <button type="submit" disabled={saving} className="btn-primary">{saving ? 'Saving…' : 'Save'}</button>
          </form>
        </div>

        {/* Tool steps */}
        <div className="bg-card border border-rim rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-rim">
            <h2 className="text-lit text-sm font-semibold">Tool Steps</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr>{['Phase', 'Tool', 'Status', 'Toggle'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr>
              </thead>
              <tbody>
                {steps.length === 0 ? (
                  <tr><td colSpan={4} className="tbl-td text-center text-dim py-8">No steps.</td></tr>
                ) : steps.map(s => (
                  <tr key={s.tool_key} className="hover:bg-hover transition-colors">
                    <td className="tbl-td text-dim text-xs">{s.phase ?? '—'}</td>
                    <td className="tbl-td text-lit font-medium">{s.label || s.tool_key}</td>
                    <td className="tbl-td"><Badge value={s.enabled !== false ? 'active' : 'inactive'} /></td>
                    <td className="tbl-td">
                      <button
                        onClick={() => handleToggle(s.tool_key)}
                        disabled={toggling === s.tool_key}
                        className="btn-ghost text-xs"
                      >
                        {toggling === s.tool_key ? '…' : s.enabled !== false ? 'Disable' : 'Enable'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent runs */}
        {recent_runs.length > 0 && (
          <div className="bg-card border border-rim rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-rim">
              <h2 className="text-lit text-sm font-semibold">Recent Runs</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr>{['Domain', 'Status', 'Started', 'Finished'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr>
                </thead>
                <tbody>
                  {recent_runs.map((r, i) => (
                    <tr key={i} className="hover:bg-hover transition-colors">
                      <td className="tbl-td font-mono text-lit">{r.domain || '—'}</td>
                      <td className="tbl-td"><Badge value={r.status} /></td>
                      <td className="tbl-td text-dim">{fmtDate(r.started_at)}</td>
                      <td className="tbl-td text-dim">{fmtDate(r.finished_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Build**

```bash
cd frontend && npm run build
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/WorkflowDetailPage.jsx && git commit -m "feat: convert WorkflowDetailPage to Tailwind with Layout"
```

---

### Task 14: InsightsPage

**Files:**
- Modify: `frontend/src/pages/InsightsPage.jsx`

- [ ] **Step 1: Rewrite `frontend/src/pages/InsightsPage.jsx`**

```jsx
import React from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { useFetch } from '../hooks/useFetch.js';

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function KpiCard({ label, value, colorCls }) {
  return (
    <div className={`rounded-xl border p-5 text-center ${colorCls}`}>
      <div className="text-3xl font-bold leading-none mb-1">{value ?? 0}</div>
      <div className="text-xs font-semibold uppercase tracking-wider opacity-80 capitalize">{label}</div>
    </div>
  );
}

function DataTable({ title, subtitle, columns, rows, renderRow, emptyMsg = 'No data.' }) {
  return (
    <div className="bg-card border border-rim rounded-xl overflow-hidden mb-5">
      {(title || subtitle) && (
        <div className="px-4 py-3 border-b border-rim">
          {title    && <h2 className="text-lit text-sm font-semibold">{title}</h2>}
          {subtitle && <p className="text-dim text-xs mt-0.5">{subtitle}</p>}
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead><tr>{columns.map(c => <th key={c} className="tbl-th">{c}</th>)}</tr></thead>
          <tbody>
            {rows && rows.length > 0
              ? rows.map((row, i) => <tr key={i} className="hover:bg-hover transition-colors">{renderRow(row, i)}</tr>)
              : <tr><td colSpan={columns.length} className="tbl-td text-center text-dim py-8">{emptyMsg}</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const SEV_TEXT = { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-blue-400', info: 'text-gray-400' };

export default function InsightsPage() {
  const { data, loading, error } = useFetch('/insights/');

  if (loading) return <Layout><div className="flex justify-center items-center h-64"><Spinner size={40} /></div></Layout>;
  if (error)   return <Layout><div className="text-red-400 p-4">Error: {error}</div></Layout>;
  if (!data)   return <Layout><div /></Layout>;

  const {
    kpi_open_critical = 0, kpi_open_high = 0, kpi_new = 0, kpi_fixed = 0,
    scan_trend = [], delta_trend = [], top_hosts = [], top_finding_types = [],
    severity_distribution = {}, top_services = [], asset_growth = [],
  } = data;

  return (
    <Layout>
      <div className="space-y-6">
        <div>
          <h1 className="text-lit text-xl font-bold">Insights</h1>
          <p className="text-dim text-sm mt-0.5">Trends and security metrics across all scans</p>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <KpiCard label="Open Critical"   value={kpi_open_critical} colorCls="text-red-400 border-red-800 bg-red-900/10" />
          <KpiCard label="Open High"       value={kpi_open_high}     colorCls="text-orange-400 border-orange-800 bg-orange-900/10" />
          <KpiCard label="New This Scan"   value={kpi_new}           colorCls="text-brand border-brand/30 bg-brand/10" />
          <KpiCard label="Fixed This Scan" value={kpi_fixed}         colorCls="text-green-400 border-green-800 bg-green-900/10" />
        </div>

        {Object.keys(severity_distribution).length > 0 && (
          <DataTable
            title="Severity Distribution" subtitle="Open findings by severity"
            columns={['Severity', 'Count']}
            rows={Object.entries(severity_distribution).sort((a, b) => {
              const order = ['critical', 'high', 'medium', 'low', 'info'];
              return order.indexOf(a[0]) - order.indexOf(b[0]);
            })}
            renderRow={([sev, cnt]) => (
              <>
                <td className="tbl-td"><Badge value={sev} /></td>
                <td className={`tbl-td font-semibold ${SEV_TEXT[sev] || 'text-body'}`}>{cnt}</td>
              </>
            )}
          />
        )}

        <DataTable
          title="Scan Trend" subtitle="Finding counts per scan session"
          columns={['Scan', 'Critical', 'High', 'Medium', 'Low', 'Total']}
          rows={scan_trend} emptyMsg="No scan trend data yet."
          renderRow={row => (
            <>
              <td className="tbl-td text-lit font-medium">{row.label || '—'}</td>
              <td className={`tbl-td ${row.critical > 0 ? 'text-red-400 font-semibold' : 'text-dim'}`}>{row.critical ?? 0}</td>
              <td className={`tbl-td ${row.high > 0 ? 'text-orange-400 font-semibold' : 'text-dim'}`}>{row.high ?? 0}</td>
              <td className={`tbl-td ${row.medium > 0 ? 'text-yellow-400 font-semibold' : 'text-dim'}`}>{row.medium ?? 0}</td>
              <td className={`tbl-td ${row.low > 0 ? 'text-blue-400 font-semibold' : 'text-dim'}`}>{row.low ?? 0}</td>
              <td className="tbl-td text-body font-semibold">{row.total ?? 0}</td>
            </>
          )}
        />

        <DataTable
          title="Delta Trend" subtitle="New vs. removed findings per scan"
          columns={['Scan', 'New Findings', 'Removed Findings']}
          rows={delta_trend} emptyMsg="No delta data yet."
          renderRow={row => (
            <>
              <td className="tbl-td text-lit font-medium">{row.label || '—'}</td>
              <td className={`tbl-td ${row.new > 0 ? 'text-red-400 font-semibold' : 'text-dim'}`}>{row.new ?? 0}</td>
              <td className={`tbl-td ${row.removed > 0 ? 'text-brand font-semibold' : 'text-dim'}`}>{row.removed ?? 0}</td>
            </>
          )}
        />

        <DataTable
          title="Top Hosts by Findings"
          columns={['Domain', 'Finding Count']} rows={top_hosts} emptyMsg="No host data."
          renderRow={row => (
            <>
              <td className="tbl-td font-mono text-lit font-medium">{row.domain}</td>
              <td className="tbl-td text-brand font-semibold">{row.count}</td>
            </>
          )}
        />

        <DataTable
          title="Top Finding Types"
          columns={['Severity', 'Title', 'Check Type', 'Occurrences', 'Last Seen']}
          rows={top_finding_types} emptyMsg="No finding type data."
          renderRow={row => (
            <>
              <td className="tbl-td"><Badge value={row.severity} /></td>
              <td className="tbl-td text-lit font-medium max-w-xs truncate">{row.title}</td>
              <td className="tbl-td font-mono text-dim text-xs">{row.check_type || '—'}</td>
              <td className="tbl-td text-brand font-semibold">{row.occurrence_count}</td>
              <td className="tbl-td text-dim text-xs">{fmtDate(row.last_seen)}</td>
            </>
          )}
        />

        {top_services.length > 0 && (
          <DataTable
            title="Top Services (CVEs)"
            columns={['Service', 'Version', 'CVE Count', 'Max CVSS']} rows={top_services}
            renderRow={row => (
              <>
                <td className="tbl-td font-mono text-lit font-medium">{row.service || '—'}</td>
                <td className="tbl-td font-mono text-dim text-xs">{row.version || '—'}</td>
                <td className={`tbl-td ${row.cve_count > 0 ? 'text-red-400 font-semibold' : 'text-dim'}`}>{row.cve_count ?? 0}</td>
                <td className={`tbl-td font-semibold ${row.max_cvss >= 7 ? 'text-red-400' : row.max_cvss >= 4 ? 'text-yellow-400' : 'text-dim'}`}>
                  {row.max_cvss != null ? row.max_cvss.toFixed(1) : '—'}
                </td>
              </>
            )}
          />
        )}

        {asset_growth.length > 0 && (
          <DataTable
            title="Asset Growth" subtitle="Asset counts per scan"
            columns={['Scan', 'Subdomains', 'Active', 'IPs', 'Ports', 'URLs']} rows={asset_growth}
            renderRow={row => (
              <>
                <td className="tbl-td text-lit font-medium">{row.label || '—'}</td>
                <td className="tbl-td text-body">{row.subdomains ?? 0}</td>
                <td className="tbl-td text-brand">{row.active_subdomains ?? 0}</td>
                <td className="tbl-td text-body">{row.ips ?? 0}</td>
                <td className="tbl-td text-body">{row.ports ?? 0}</td>
                <td className="tbl-td text-body">{row.urls ?? 0}</td>
              </>
            )}
          />
        )}
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Build**

```bash
cd frontend && npm run build
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/InsightsPage.jsx && git commit -m "feat: convert InsightsPage to Tailwind with Layout"
```

---

### Task 15: HTMX Retirement + SPA Catch-All

**Files:**
- Modify: `openeasd/urls.py`
- Modify: `CLAUDE.md`

Do NOT delete `templates/` directory until user confirms — the catch-all makes HTMX routes unreachable in practice.

- [ ] **Step 1: Read `openeasd/urls.py`**

- [ ] **Step 2: Add SPA catch-all to the END of urlpatterns in `openeasd/urls.py`**

Add imports at the top if not already present:

```python
from django.views.generic import TemplateView
from django.urls import re_path
```

Add this as the very last entry in `urlpatterns`:

```python
re_path(
    r'^(?!api/|admin/|accounts/|static/|media/).*$',
    TemplateView.as_view(template_name='index.html'),
    name='spa',
),
```

- [ ] **Step 3: Verify `openeasd/settings.py` serves the React build**

Check that `TEMPLATES[0]['DIRS']` includes `BASE_DIR / 'frontend' / 'dist'` and `STATICFILES_DIRS` includes `BASE_DIR / 'frontend' / 'dist' / 'assets'`. If missing, add them:

```python
TEMPLATES = [
    {
        ...
        'DIRS': [BASE_DIR / 'frontend' / 'dist'],   # ← add if missing
        ...
    }
]

STATICFILES_DIRS = [BASE_DIR / 'frontend' / 'dist' / 'assets']   # ← add if missing
```

- [ ] **Step 4: Build React and run Django check**

```bash
cd frontend && npm run build && cd ..
uv run manage.py check
```

Expected: no errors.

- [ ] **Step 5: Run fast tests**

```bash
uv run pytest tests/ --ignore=tests/unit/test_domain_security.py
```

Expected: all pass.

- [ ] **Step 6: Update `CLAUDE.md` — Frontend rules section**

Add after the existing Frontend rules bullet list:

```markdown
- Legacy HTMX/Alpine/Django-template stack is **retired**. All UI is the React SPA.
- SPA catch-all in `openeasd/urls.py` serves `frontend/dist/index.html` for all non-API paths.
- Run `cd frontend && npm run build` to update the production bundle before deployment.
```

- [ ] **Step 7: Commit**

```bash
git add openeasd/urls.py openeasd/settings.py CLAUDE.md
git commit -m "feat: add SPA catch-all route; retire HTMX/Alpine frontend stack"
```

---

## Self-Review

### Spec coverage

| Spec requirement | Task |
|---|---|
| Tailwind npm install + tailwind.config.js + postcss.config.js | 1 |
| Semantic color theme: brand/canvas/card/rim/dim/lit/body/hover | 1 |
| @layer components: badge-*, tbl-th, tbl-td, field, btn-* | 1 |
| Badge → Tailwind pill via CSS class lookup | 2 |
| Spinner → animate-spin | 2 |
| Pagination, ConfirmButton, Notification → Tailwind | 2 |
| Layout: fixed w-56 sidebar, nav, badge counts from /api/dashboard/ | 3 |
| App.jsx: /scans/start route before /scans/:uuid | 4 |
| usePolling: 401 redirect fix | 4 |
| LoginPage: no Layout | 5 |
| DashboardPage, DomainsPage, ScanStartPage (new) | 6, 7, 8 |
| ScansPage: Stop button for running scans | 9 |
| ScanDetailPage, FindingsPage, WorkflowsPage, WorkflowDetailPage, InsightsPage | 10–14 |
| HTMX retirement + SPA catch-all | 15 |

All spec requirements covered. No gaps.

### Placeholder scan

No TBD/TODO/"similar to Task N"/missing code found.

### Type consistency

- `Badge` prop: `value` — consistent throughout.
- `ConfirmButton` props: `label`, `confirmLabel`, `onConfirm`, `disabled` — consistent in Tasks 2, 7, 9, 10, 12, 13.
- `Layout` prop: `children` — consistent.
- `Notification` props: `message`, `type`, `key` — consistent.
- `useFetch` / `usePolling` return `{ data, loading, error, refetch }` — consistent.
- `navigate` from `'../App.jsx'` — consistent all pages.
- `apiPost` / `apiFetch` from `'../api/client.js'` — consistent.
