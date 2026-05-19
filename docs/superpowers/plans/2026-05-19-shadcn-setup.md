# shadcn/ui Setup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the OpenEASD React frontend from hand-rolled components to shadcn/ui, replacing Badge, ConfirmButton, Notification, and Pagination with shadcn equivalents, and updating all pages to use shadcn Button, Table, and Card.

**Architecture:** Install shadcn/ui with CSS-variable-based dark theme mapped to the existing palette, add the `@` Vite path alias, then progressively replace components and update all 10 pages. The existing semantic Tailwind colors (`brand`, `canvas`, `rim`, etc.) are replaced by CSS variables so shadcn internals and existing page code share the same resolved colors.

**Tech Stack:** React 18, Vite 5, Tailwind CSS 3, shadcn/ui (Radix UI primitives), class-variance-authority, clsx, tailwind-merge, sonner (toasts)

---

### Task 1: Add Vite `@` path alias

**Files:**
- Modify: `frontend/vite.config.js`

- [ ] **Step 1: Update vite.config.js**

Replace the full file content:

```js
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  base: '/static/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/accounts': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
});
```

- [ ] **Step 2: Commit**

```bash
cd frontend && git add vite.config.js
git commit -m "feat(frontend): add @ path alias to Vite config for shadcn"
```

---

### Task 2: Install npm packages

**Files:** `frontend/package.json` (modified by npm)

- [ ] **Step 1: Install shadcn peer dependencies**

```bash
cd frontend && npm install class-variance-authority clsx tailwind-merge @radix-ui/react-slot @radix-ui/react-alert-dialog lucide-react sonner
```

Expected: packages added to `node_modules`, `package.json` and `package-lock.json` updated.

- [ ] **Step 2: Commit**

```bash
cd frontend && git add package.json package-lock.json
git commit -m "feat(frontend): install shadcn peer deps (cva, clsx, radix-ui, sonner)"
```

---

### Task 3: Create `components.json` and `src/lib/utils.js`

**Files:**
- Create: `frontend/components.json`
- Create: `frontend/src/lib/utils.js`

- [ ] **Step 1: Create components.json**

```json
{
  "$schema": "https://ui.shadcn.com/schema.json",
  "style": "default",
  "rsc": false,
  "tsx": false,
  "tailwind": {
    "config": "tailwind.config.js",
    "css": "src/index.css",
    "baseColor": "slate",
    "cssVariables": true,
    "prefix": ""
  },
  "aliases": {
    "components": "@/components",
    "utils": "@/lib/utils",
    "ui": "@/components/ui",
    "lib": "@/lib",
    "hooks": "@/hooks"
  },
  "iconLibrary": "lucide"
}
```

- [ ] **Step 2: Create src/lib/utils.js**

```js
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs) {
  return twMerge(clsx(inputs));
}
```

- [ ] **Step 3: Commit**

```bash
cd frontend && git add components.json src/lib/utils.js
git commit -m "feat(frontend): add shadcn components.json config and cn() utility"
```

---

### Task 4: Update Tailwind config and CSS variables

**Files:**
- Modify: `frontend/tailwind.config.js`
- Modify: `frontend/src/index.css`

- [ ] **Step 1: Replace tailwind.config.js**

```js
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // semantic names kept for existing page code
        brand:  '#30c074',
        canvas: '#0d1117',
        rim:    '#30363d',
        dim:    '#8b949e',
        lit:    '#e6edf3',
        body:   '#c9d1d9',
        hover:  '#1c2128',
        // shadcn CSS-variable colors
        border: 'hsl(var(--border))',
        input:  'hsl(var(--input))',
        ring:   'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
        },
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))',
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))',
        },
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))',
        },
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))',
        },
        popover: {
          DEFAULT: 'hsl(var(--popover))',
          foreground: 'hsl(var(--popover-foreground))',
        },
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))',
        },
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
      fontFamily: {
        sans: ["'Segoe UI'", 'system-ui', '-apple-system', 'sans-serif'],
      },
    },
  },
  plugins: [],
};
```

- [ ] **Step 2: Prepend CSS variables to index.css**

Replace the top of `src/index.css` (keep all existing `@layer components` content, just change the top):

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  :root {
    --background: 215 28% 7%;
    --foreground: 210 26% 93%;
    --card: 214 22% 11%;
    --card-foreground: 210 26% 93%;
    --popover: 214 22% 11%;
    --popover-foreground: 210 26% 93%;
    --primary: 145 60% 47%;
    --primary-foreground: 215 28% 7%;
    --secondary: 214 18% 13%;
    --secondary-foreground: 210 17% 82%;
    --muted: 214 18% 13%;
    --muted-foreground: 211 8% 58%;
    --accent: 214 18% 13%;
    --accent-foreground: 210 17% 82%;
    --destructive: 0 72% 51%;
    --destructive-foreground: 0 0% 98%;
    --border: 210 12% 21%;
    --input: 210 12% 21%;
    --ring: 145 60% 47%;
    --radius: 0.5rem;
  }
}

@layer components {
  /* Keep all existing .badge-*, .tbl-*, .field, .btn-* classes intact — removed in Task 19 */
```

Keep the rest of the file unchanged (all existing `@layer components` rules stay until Task 21).

- [ ] **Step 3: Commit**

```bash
cd frontend && git add tailwind.config.js src/index.css
git commit -m "feat(frontend): add shadcn CSS variables to Tailwind config and index.css"
```

---

### Task 5: Add shadcn components via CLI

**Files created in `frontend/src/components/ui/`:**
- `button.jsx`, `badge.jsx`, `table.jsx`, `card.jsx`, `alert-dialog.jsx`, `pagination.jsx`
- Sonner installed as a package (not a UI file)

- [ ] **Step 1: Run shadcn add**

```bash
cd frontend && npx shadcn@latest add button badge table card alert-dialog pagination --overwrite
```

Expected: files created in `src/components/ui/`. If prompted to install additional Radix UI packages (e.g. `@radix-ui/react-pagination`), confirm with `y`. The `--overwrite` flag prevents re-prompting for existing files.

- [ ] **Step 2: Install sonner toast component**

shadcn's toast uses sonner directly:
```bash
cd frontend && npx shadcn@latest add sonner --yes
```

Expected: `src/components/ui/sonner.jsx` created.

- [ ] **Step 3: Commit**

```bash
cd frontend && git add src/components/ui/
git commit -m "feat(frontend): add shadcn ui components (button, badge, table, card, alert-dialog, pagination, sonner)"
```

---

### Task 6: Customize Button variants

**Files:**
- Modify: `frontend/src/components/ui/button.jsx`

The shadcn default Button needs two custom variants: `outline` styled to match `btn-ghost` (hover:border-primary hover:text-primary), and `danger` styled to match `btn-danger` (hover:border-destructive hover:text-destructive).

- [ ] **Step 1: Replace button.jsx**

```jsx
import * as React from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cva } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0',
  {
    variants: {
      variant: {
        default:     'bg-primary text-primary-foreground shadow hover:bg-primary/90',
        destructive: 'bg-destructive text-destructive-foreground shadow-sm hover:bg-destructive/90',
        outline:     'border border-border bg-transparent text-foreground shadow-sm hover:border-primary hover:text-primary',
        secondary:   'bg-secondary text-secondary-foreground shadow-sm hover:bg-secondary/80',
        ghost:       'hover:bg-accent hover:text-accent-foreground',
        link:        'text-primary underline-offset-4 hover:underline',
        danger:      'border border-border bg-transparent text-foreground shadow-sm hover:border-destructive hover:text-red-400',
      },
      size: {
        default: 'h-9 px-4 py-2',
        sm:      'h-8 rounded-md px-3 text-xs',
        lg:      'h-10 rounded-md px-8',
        icon:    'h-9 w-9',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

function Button({ className, variant, size, asChild = false, ...props }) {
  const Comp = asChild ? Slot : 'button';
  return (
    <Comp className={cn(buttonVariants({ variant, size, className }))} {...props} />
  );
}

export { Button, buttonVariants };
```

- [ ] **Step 2: Commit**

```bash
cd frontend && git add src/components/ui/button.jsx
git commit -m "feat(frontend): customize Button variants (outline=btn-ghost, danger=btn-danger)"
```

---

### Task 7: Replace Badge.jsx

**Files:**
- Modify: `frontend/src/components/Badge.jsx`

- [ ] **Step 1: Replace Badge.jsx**

```jsx
import React from 'react';
import { cva } from 'class-variance-authority';
import { cn } from '../lib/utils.js';

const badgeVariants = cva(
  'inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold capitalize border',
  {
    variants: {
      variant: {
        critical:       'bg-red-900/40 text-red-400 border-red-800',
        high:           'bg-orange-900/40 text-orange-400 border-orange-800',
        medium:         'bg-yellow-900/40 text-yellow-400 border-yellow-800',
        low:            'bg-blue-900/40 text-blue-400 border-blue-800',
        info:           'bg-gray-800/60 text-gray-400 border-gray-700',
        pending:        'bg-gray-800/60 text-gray-400 border-gray-700',
        running:        'bg-blue-900/40 text-blue-400 border-blue-800',
        completed:      'bg-green-900/40 text-green-400 border-green-800',
        failed:         'bg-red-900/40 text-red-400 border-red-800',
        cancelled:      'bg-gray-800/60 text-gray-400 border-gray-700',
        scheduled:      'bg-yellow-900/40 text-yellow-400 border-yellow-800',
        open:           'bg-red-900/40 text-red-400 border-red-800',
        acknowledged:   'bg-yellow-900/40 text-yellow-400 border-yellow-800',
        in_progress:    'bg-blue-900/40 text-blue-400 border-blue-800',
        resolved:       'bg-green-900/40 text-green-400 border-green-800',
        false_positive: 'bg-gray-800/60 text-gray-400 border-gray-700',
        active:         'bg-green-900/40 text-green-400 border-green-800',
        inactive:       'bg-gray-800/60 text-gray-400 border-gray-700',
        idle:           'bg-gray-800/60 text-gray-400 border-gray-700',
        web:            'bg-blue-900/40 text-blue-400 border-blue-800',
        fallback:       'bg-gray-800/60 text-gray-400 border-gray-700',
      },
    },
    defaultVariants: { variant: 'fallback' },
  }
);

const KNOWN = new Set([
  'critical','high','medium','low','info','pending','running','completed','failed',
  'cancelled','scheduled','open','acknowledged','in_progress','resolved',
  'false_positive','active','inactive','idle','web',
]);

export function Badge({ value }) {
  const label   = value ?? '—';
  const variant = KNOWN.has(label) ? label : 'fallback';
  return (
    <span className={cn(badgeVariants({ variant }))}>
      {label.replace(/_/g, ' ')}
    </span>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd frontend && git add src/components/Badge.jsx
git commit -m "feat(frontend): rebuild Badge with cva variants (shadcn-style)"
```

---

### Task 8: Replace Notification.jsx with Sonner, update main.jsx

**Files:**
- Modify: `frontend/src/components/Notification.jsx`
- Modify: `frontend/src/main.jsx`

All pages currently render `<Notification key={...} message={...} type={...} />` and call `notify(msg, type)`. After this task, `Notification.jsx` re-exports `toast` from sonner so pages need zero import changes — they just call `toast.success(msg)` or `toast.error(msg)`. The `<Notification>` JSX render in pages is removed.

- [ ] **Step 1: Replace Notification.jsx**

```jsx
export { toast } from 'sonner';
```

- [ ] **Step 2: Update main.jsx to include Toaster**

```jsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App.jsx';
import { Toaster } from './components/ui/sonner.jsx';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
    <Toaster theme="dark" position="top-right" richColors />
  </React.StrictMode>
);
```

- [ ] **Step 3: Commit**

```bash
cd frontend && git add src/components/Notification.jsx src/main.jsx
git commit -m "feat(frontend): replace Notification component with sonner toast"
```

---

### Task 9: Replace ConfirmButton.jsx

**Files:**
- Modify: `frontend/src/components/ConfirmButton.jsx`

API stays identical: `{ label, confirmLabel, onConfirm, disabled }`. All existing pages work without import changes.

- [ ] **Step 1: Replace ConfirmButton.jsx**

```jsx
import React from 'react';
import { Button } from './ui/button.jsx';
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel,
  AlertDialogContent, AlertDialogDescription,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
  AlertDialogTrigger,
} from './ui/alert-dialog.jsx';

export function ConfirmButton({ label = 'Delete', confirmLabel = 'Are you sure?', onConfirm, disabled }) {
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="danger" size="sm" disabled={disabled}>{label}</Button>
      </AlertDialogTrigger>
      <AlertDialogContent className="bg-card border-border text-foreground">
        <AlertDialogHeader>
          <AlertDialogTitle>{confirmLabel}</AlertDialogTitle>
          <AlertDialogDescription className="text-muted-foreground">
            This action cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel className="border-border text-foreground hover:bg-accent">Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={onConfirm}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            Confirm
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd frontend && git add src/components/ConfirmButton.jsx
git commit -m "feat(frontend): replace ConfirmButton with shadcn AlertDialog"
```

---

### Task 10: Replace Pagination.jsx

**Files:**
- Modify: `frontend/src/components/Pagination.jsx`

API stays identical: `{ page, totalPages, onPage }`.

- [ ] **Step 1: Replace Pagination.jsx**

```jsx
import React from 'react';
import {
  Pagination as ShadcnPagination,
  PaginationContent,
  PaginationItem,
  PaginationNext,
  PaginationPrevious,
} from './ui/pagination.jsx';

export function Pagination({ page, totalPages, onPage }) {
  if (!totalPages || totalPages <= 1) return null;
  return (
    <ShadcnPagination>
      <PaginationContent>
        <PaginationItem>
          <PaginationPrevious
            onClick={() => onPage(page - 1)}
            className={page <= 1 ? 'pointer-events-none opacity-50' : 'cursor-pointer'}
          />
        </PaginationItem>
        <PaginationItem>
          <span className="text-sm text-muted-foreground px-4">
            Page {page} of {totalPages}
          </span>
        </PaginationItem>
        <PaginationItem>
          <PaginationNext
            onClick={() => onPage(page + 1)}
            className={page >= totalPages ? 'pointer-events-none opacity-50' : 'cursor-pointer'}
          />
        </PaginationItem>
      </PaginationContent>
    </ShadcnPagination>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd frontend && git add src/components/Pagination.jsx
git commit -m "feat(frontend): replace Pagination with shadcn Pagination"
```

---

### Task 11: Update LoginPage.jsx

**Files:**
- Modify: `frontend/src/pages/LoginPage.jsx`

Changes: `<button className="btn-primary">` → `<Button>`, `input className="field"` stays (no shadcn Input needed).

- [ ] **Step 1: Replace LoginPage.jsx**

```jsx
import React, { useState } from 'react';
import { Button } from '../components/ui/button.jsx';
import { apiPost } from '../api/client.js';
import { auth } from '../auth.js';
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
      const res = await apiPost('/token/pair', { username, password });
      auth.setTokens(res.access, res.refresh);
      navigate('/');
    } catch (err) {
      setError(err.data?.error?.message || err.message || 'Login failed');
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
          <Button type="submit" disabled={loading} className="w-full mt-2">
            {loading ? 'Signing in…' : 'Sign in'}
          </Button>
        </form>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd frontend && git add src/pages/LoginPage.jsx
git commit -m "feat(frontend): migrate LoginPage to shadcn Button"
```

---

### Task 12: Update DashboardPage.jsx

**Files:**
- Modify: `frontend/src/pages/DashboardPage.jsx`

Changes: `tbl-th`/`tbl-td` → shadcn Table, card divs → shadcn Card, `btn-ghost` → `Button variant="outline"`.

- [ ] **Step 1: Replace DashboardPage.jsx**

```jsx
import React from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
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

        <Card className="overflow-hidden">
          <CardHeader className="border-b border-border px-4 py-3">
            <CardTitle className="text-sm font-semibold">Domain Status</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    {['Domain', 'Status', 'Last Scan', 'Critical', 'High', 'Actions'].map(h => (
                      <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {domain_status.length === 0 ? (
                    <TableRow><TableCell colSpan={6} className="px-4 py-8 text-center text-dim">No domains yet.</TableCell></TableRow>
                  ) : domain_status.map(d => (
                    <TableRow key={d.id} className="hover:bg-hover transition-colors">
                      <TableCell className="px-4 py-3 text-lit font-mono font-medium">{d.domain}</TableCell>
                      <TableCell className="px-4 py-3"><Badge value={d.scan_status || 'idle'} /></TableCell>
                      <TableCell className="px-4 py-3 text-dim">{d.last_scan ? new Date(d.last_scan).toLocaleDateString() : '—'}</TableCell>
                      <TableCell className="px-4 py-3 text-red-400 font-semibold">{d.critical ?? 0}</TableCell>
                      <TableCell className="px-4 py-3 text-orange-400 font-semibold">{d.high ?? 0}</TableCell>
                      <TableCell className="px-4 py-3">
                        <Button variant="outline" size="sm" onClick={() => navigate('/scans?domain=' + d.domain)}>View Scans</Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {urgent_findings.length > 0 && (
          <Card className="overflow-hidden">
            <CardHeader className="border-b border-border px-4 py-3">
              <CardTitle className="text-sm font-semibold">Urgent Findings</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      {['Severity', 'Title', 'Domain', 'Source'].map(h => (
                        <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {urgent_findings.map(f => (
                      <TableRow key={f.id} className="hover:bg-hover transition-colors">
                        <TableCell className="px-4 py-3"><Badge value={f.severity} /></TableCell>
                        <TableCell className="px-4 py-3 text-body font-medium max-w-xs truncate">{f.title}</TableCell>
                        <TableCell className="px-4 py-3 text-dim font-mono text-xs">{f.domain}</TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs">{f.source}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd frontend && git add src/pages/DashboardPage.jsx
git commit -m "feat(frontend): migrate DashboardPage to shadcn Card, Table, Button"
```

---

### Task 13: Update DomainsPage.jsx

**Files:**
- Modify: `frontend/src/pages/DomainsPage.jsx`

Changes: `btn-primary`/`btn-ghost` → `Button`, `tbl-*` → shadcn Table, card divs → shadcn Card, `<Notification>` state removed → `toast` calls.

- [ ] **Step 1: Replace DomainsPage.jsx**

```jsx
import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { ConfirmButton } from '../components/ConfirmButton.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import { toast } from '../components/Notification.jsx';
import { navigate } from '../App.jsx';
import { apiPost } from '../api/client.js';
import { useFetch } from '../hooks/useFetch.js';

function findingTotal(summary) {
  if (!summary || typeof summary !== 'object') return 0;
  return Object.values(summary).reduce((s, n) => s + (n || 0), 0);
}

function AddDomainForm({ onAdded }) {
  const [domain,  setDomain]  = useState('');
  const [saving,  setSaving]  = useState(false);
  const [err,     setErr]     = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!domain.trim()) { setErr('Domain is required.'); return; }
    setSaving(true); setErr(null);
    try {
      await apiPost('/domains/', { name: domain.trim() });
      setDomain('');
      onAdded();
    } catch (e) {
      setErr(e.message || 'Failed to add domain.');
    } finally { setSaving(false); }
  }

  return (
    <Card className="mb-5">
      <CardHeader className="border-b border-border px-5 py-4">
        <CardTitle className="text-sm font-semibold">Add Domain</CardTitle>
      </CardHeader>
      <CardContent className="px-5 py-4">
        <form onSubmit={handleSubmit} className="flex gap-3 flex-wrap">
          <input value={domain} onChange={e => setDomain(e.target.value)}
            placeholder="example.com" className="field flex-1 min-w-48" />
          <Button type="submit" disabled={saving}>
            {saving ? 'Adding…' : 'Add Domain'}
          </Button>
        </form>
        {err && <p className="text-red-400 text-xs mt-2">{err}</p>}
      </CardContent>
    </Card>
  );
}

export default function DomainsPage() {
  const { data, loading, error, refetch } = useFetch('/domains/');
  const [busyIds, setBusyIds] = useState(new Set());

  const domains = data || [];
  function busy(id) { return busyIds.has(id); }
  function setBusy(id, val) {
    setBusyIds(s => { const ns = new Set(s); val ? ns.add(id) : ns.delete(id); return ns; });
  }

  async function handleToggle(id) {
    setBusy(id, true);
    try { await apiPost(`/domains/${id}/toggle/`); refetch(); }
    catch (e) { toast.error(e.message || 'Toggle failed.'); }
    finally { setBusy(id, false); }
  }

  async function handleDelete(id, name) {
    setBusy(id, true);
    try { await apiPost(`/domains/${id}/delete/`); toast.success(`"${name}" deleted.`); refetch(); }
    catch (e) { toast.error(e.message || 'Delete failed.'); }
    finally { setBusy(id, false); }
  }

  return (
    <Layout>
      <div className="space-y-5">
        <div>
          <h1 className="text-lit text-xl font-bold">Domains</h1>
          <p className="text-dim text-sm mt-0.5">Manage monitored domains</p>
        </div>
        <AddDomainForm onAdded={() => { toast.success('Domain added.'); refetch(); }} />
        <Card className="overflow-hidden">
          {loading ? <div className="flex justify-center p-8"><Spinner /></div>
          : error   ? <div className="p-6 text-red-400 text-sm">Error: {error}</div>
          : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    {['Domain', 'Active', 'Last Scan', 'Findings', 'Actions'].map(h => (
                      <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {domains.length === 0 ? (
                    <TableRow><TableCell colSpan={5} className="px-4 py-10 text-center text-dim">No domains yet.</TableCell></TableRow>
                  ) : domains.map(d => (
                    <TableRow key={d.id} className={`hover:bg-hover transition-colors ${busy(d.id) ? 'opacity-50' : ''}`}>
                      <TableCell className="px-4 py-3 text-lit font-mono font-medium">{d.name}</TableCell>
                      <TableCell className="px-4 py-3"><Badge value={d.is_active ? 'active' : 'inactive'} /></TableCell>
                      <TableCell className="px-4 py-3 text-dim">
                        {d.last_scan?.start_time ? new Date(d.last_scan.start_time).toLocaleDateString() : '—'}
                      </TableCell>
                      <TableCell className="px-4 py-3 text-dim">{findingTotal(d.findings_summary) || '—'}</TableCell>
                      <TableCell className="px-4 py-3">
                        <span className="inline-flex gap-1.5 items-center flex-wrap">
                          <Button variant="outline" size="sm" onClick={() => navigate(`/scans/start?domain=${d.name}`)}>Scan</Button>
                          <Button variant="outline" size="sm" onClick={() => navigate('/scans?domain=' + d.name)}>History</Button>
                          <Button variant="outline" size="sm" onClick={() => handleToggle(d.id)} disabled={busy(d.id)}>
                            {d.is_active ? 'Deactivate' : 'Activate'}
                          </Button>
                          <ConfirmButton label="Delete" disabled={busy(d.id)} onConfirm={() => handleDelete(d.id, d.name)} />
                        </span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </Card>
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd frontend && git add src/pages/DomainsPage.jsx
git commit -m "feat(frontend): migrate DomainsPage to shadcn Card, Table, Button, toast"
```

---

### Task 14: Update ScansPage.jsx

**Files:**
- Modify: `frontend/src/pages/ScansPage.jsx`

- [ ] **Step 1: Replace ScansPage.jsx**

```jsx
import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Pagination } from '../components/Pagination.jsx';
import { ConfirmButton } from '../components/ConfirmButton.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import { toast } from '../components/Notification.jsx';
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
  const [busyIds, setBusyIds] = useState(new Set());

  const { data: domainsData } = useFetch('/domains/');
  const { data: scansData, pagination, loading, error, refetch } = useFetch(
    `/scans/?domain=${domain}&status=${status}&page=${page}`,
    [domain, status, page],
  );
  const { data: scheduledData, refetch: refetchScheduled } = useFetch('/scheduled/');

  const scans     = scansData?.results ?? [];
  const scheduled = scheduledData || [];
  const domains   = domainsData || [];

  function busy(id) { return busyIds.has(id); }
  function setBusy(id, val) {
    setBusyIds(s => { const ns = new Set(s); val ? ns.add(id) : ns.delete(id); return ns; });
  }

  async function handleStop(uuid) {
    setBusy(uuid, true);
    try { await apiPost(`/scans/${uuid}/stop/`); toast.success('Scan stopped.'); refetch(); }
    catch (e) { toast.error(e.message || 'Stop failed.'); }
    finally { setBusy(uuid, false); }
  }

  async function handleDelete(uuid) {
    setBusy(uuid, true);
    try { await apiPost(`/scans/${uuid}/delete/`); toast.success('Scan deleted.'); refetch(); }
    catch (e) { toast.error(e.message || 'Delete failed.'); }
    finally { setBusy(uuid, false); }
  }

  async function handleCancelJob(jobId) {
    try { await apiPost(`/scheduled/${jobId}/cancel/`); toast.success('Job cancelled.'); refetchScheduled(); }
    catch (e) { toast.error(e.message || 'Cancel failed.'); }
  }

  return (
    <Layout>
      <div className="space-y-5">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h1 className="text-lit text-xl font-bold">Scans</h1>
            <p className="text-dim text-sm mt-0.5">Scan history and scheduled jobs</p>
          </div>
          <Button onClick={() => navigate('/scans/start')}>+ New Scan</Button>
        </div>

        <div className="flex gap-3 flex-wrap">
          <select value={domain} onChange={e => { setDomain(e.target.value); setPage(1); }} className="field w-52">
            <option value="">All domains</option>
            {domains.map(d => <option key={d.id} value={d.name}>{d.name}</option>)}
          </select>
          <select value={status} onChange={e => { setStatus(e.target.value); setPage(1); }} className="field w-40">
            <option value="">All statuses</option>
            {['pending', 'running', 'completed', 'failed', 'cancelled'].map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>

        <Card className="overflow-hidden">
          <CardHeader className="border-b border-border px-4 py-3">
            <CardTitle className="text-sm font-semibold">Scan Sessions</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? <div className="flex justify-center p-8"><Spinner /></div>
            : error   ? <div className="p-6 text-red-400 text-sm">Error: {error}</div>
            : (
              <>
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        {['Domain', 'Status', 'Started', 'Findings', 'Actions'].map(h => (
                          <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                        ))}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {scans.length === 0 ? (
                        <TableRow><TableCell colSpan={5} className="px-4 py-10 text-center text-dim">No scans yet.</TableCell></TableRow>
                      ) : scans.map(s => (
                        <TableRow key={s.uuid} className={`hover:bg-hover transition-colors ${busy(s.uuid) ? 'opacity-50' : ''}`}>
                          <TableCell className="px-4 py-3 text-lit font-mono font-medium">{s.domain_name || '—'}</TableCell>
                          <TableCell className="px-4 py-3"><Badge value={s.status} /></TableCell>
                          <TableCell className="px-4 py-3 text-dim">{fmtDate(s.start_time)}</TableCell>
                          <TableCell className="px-4 py-3 text-body">{s.total_findings ?? '—'}</TableCell>
                          <TableCell className="px-4 py-3">
                            <span className="inline-flex gap-1.5 items-center flex-wrap">
                              <Button variant="outline" size="sm" onClick={() => navigate(`/scans/${s.uuid}`)}>View</Button>
                              {s.status === 'running' && (
                                <ConfirmButton label="Stop" confirmLabel="Stop scan?" onConfirm={() => handleStop(s.uuid)} disabled={busy(s.uuid)} />
                              )}
                              {['completed', 'failed', 'cancelled'].includes(s.status) && (
                                <ConfirmButton label="Delete" onConfirm={() => handleDelete(s.uuid)} disabled={busy(s.uuid)} />
                              )}
                            </span>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
                {pagination && (
                  <div className="px-4 py-3 border-t border-border">
                    <Pagination page={pagination.page} totalPages={pagination.total_pages} onPage={setPage} />
                  </div>
                )}
              </>
            )}
          </CardContent>
        </Card>

        {scheduled.length > 0 && (
          <Card className="overflow-hidden">
            <CardHeader className="border-b border-border px-4 py-3">
              <CardTitle className="text-sm font-semibold">Scheduled Jobs</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      {['Domain', 'Type', 'Next Run', 'Actions'].map(h => (
                        <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scheduled.map(j => (
                      <TableRow key={j.job_id} className="hover:bg-hover transition-colors">
                        <TableCell className="px-4 py-3 font-mono text-lit">{j.domain || '—'}</TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs">{j.job_type || '—'}</TableCell>
                        <TableCell className="px-4 py-3 text-dim">{fmtDate(j.next_run_time)}</TableCell>
                        <TableCell className="px-4 py-3">
                          <ConfirmButton label="Cancel" confirmLabel="Cancel job?" onConfirm={() => handleCancelJob(j.job_id)} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd frontend && git add src/pages/ScansPage.jsx
git commit -m "feat(frontend): migrate ScansPage to shadcn Card, Table, Button, toast"
```

---

### Task 15: Update FindingsPage.jsx

**Files:**
- Modify: `frontend/src/pages/FindingsPage.jsx`

- [ ] **Step 1: Replace FindingsPage.jsx**

```jsx
import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Pagination } from '../components/Pagination.jsx';
import { Card, CardContent } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import { toast } from '../components/Notification.jsx';
import { apiPost } from '../api/client.js';
import { useFetch } from '../hooks/useFetch.js';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES   = ['open', 'acknowledged', 'in_progress', 'resolved', 'false_positive'];

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
        {STATUSES.map(s => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
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

  const { data: domainsData } = useFetch('/domains/');
  const { data, loading, error, pagination, refetch } = useFetch(
    `/scans/findings/?severity=${severity}&status=${status}&domain=${domain}&page=${page}`,
    [severity, status, domain, page],
  );

  const findings = data?.findings ?? [];
  const domains  = domainsData || [];

  return (
    <Layout>
      <div className="space-y-5">
        <div>
          <h1 className="text-lit text-xl font-bold">Findings</h1>
          <p className="text-dim text-sm mt-0.5">All findings across all scans</p>
        </div>

        <div className="flex gap-3 flex-wrap">
          <select value={severity} onChange={e => { setSeverity(e.target.value); setPage(1); }} className="field w-36">
            <option value="">All severities</option>
            {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={status} onChange={e => { setStatus(e.target.value); setPage(1); }} className="field w-40">
            <option value="">All statuses</option>
            {STATUSES.map(s => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
          </select>
          <select value={domain} onChange={e => { setDomain(e.target.value); setPage(1); }} className="field w-52">
            <option value="">All domains</option>
            {domains.map(d => <option key={d.id} value={d.name}>{d.name}</option>)}
          </select>
        </div>

        <Card className="overflow-hidden">
          {loading ? <div className="flex justify-center p-8"><Spinner /></div>
          : error   ? <div className="p-6 text-red-400 text-sm">Error: {error}</div>
          : (
            <>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      {['Severity', 'Title', 'Target', 'Source', 'Status', 'Found'].map(h => (
                        <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {findings.length === 0 ? (
                      <TableRow><TableCell colSpan={6} className="px-4 py-10 text-center text-dim">No findings.</TableCell></TableRow>
                    ) : findings.map(f => (
                      <TableRow key={f.id} className="hover:bg-hover transition-colors">
                        <TableCell className="px-4 py-3"><Badge value={f.severity} /></TableCell>
                        <TableCell className="px-4 py-3 text-body font-medium max-w-xs truncate">{f.title}</TableCell>
                        <TableCell className="px-4 py-3 font-mono text-dim text-xs">{f.target}</TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs">{f.source}</TableCell>
                        <TableCell className="px-4 py-3">
                          <StatusEditor findingId={f.id} current={f.status || 'open'}
                            onUpdated={() => { toast.success('Status updated.'); refetch(); }} />
                        </TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs">{fmtDate(f.discovered_at)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              {pagination && (
                <div className="px-4 py-3 border-t border-border">
                  <Pagination page={pagination.page} totalPages={pagination.total_pages} onPage={setPage} />
                </div>
              )}
            </>
          )}
        </Card>
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd frontend && git add src/pages/FindingsPage.jsx
git commit -m "feat(frontend): migrate FindingsPage to shadcn Card, Table, toast"
```

---

### Task 16: Update ScanDetailPage.jsx

**Files:**
- Modify: `frontend/src/pages/ScanDetailPage.jsx`

Notable: `<a className="btn-secondary">` (undefined class) → `<Button variant="outline" asChild>`.

- [ ] **Step 1: Replace ScanDetailPage.jsx**

```jsx
import React, { useState, useEffect, useRef } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { ConfirmButton } from '../components/ConfirmButton.jsx';
import { Pagination } from '../components/Pagination.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import { toast } from '../components/Notification.jsx';
import { navigate } from '../App.jsx';
import { apiPost } from '../api/client.js';
import { auth } from '../auth.js';
import { useFetch } from '../hooks/useFetch.js';
import { usePolling } from '../hooks/usePolling.js';

const TABS = ['subdomains', 'ips', 'ports', 'urls', 'findings'];
const TERMINAL = new Set(['completed', 'failed', 'cancelled']);
const PAGE_SIZE = 50;

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function fmtSize(bytes) {
  if (bytes == null) return '—';
  if (bytes === 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1_048_576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1_048_576).toFixed(1)} MB`;
}

function statusColor(code) {
  if (!code) return 'text-dim';
  if (code < 300) return 'text-green-400';
  if (code < 400) return 'text-yellow-400';
  if (code < 500) return 'text-orange-400';
  return 'text-red-400';
}

const SCHEME_CLS = {
  https: 'bg-blue-900/40 text-blue-400 border border-blue-800',
  http:  'bg-yellow-900/40 text-yellow-400 border border-yellow-800',
};

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
  const [busy, setBusy] = useState(false);
  const [schemeFilter, setSchemeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  const { data, loading, error, refetch } = useFetch(uuid ? `/scans/${uuid}/` : null, [uuid]);

  const currentStatus = data?.session?.status;
  const pollPath = uuid && currentStatus && !TERMINAL.has(currentStatus)
    ? `/scans/${uuid}/status/` : null;
  const { data: statusData } = usePolling(pollPath, 3000);

  const prevPollStatusRef = useRef(null);
  useEffect(() => {
    const pollStatus = statusData?.session?.status;
    if (
      pollStatus &&
      TERMINAL.has(pollStatus) &&
      prevPollStatusRef.current &&
      !TERMINAL.has(prevPollStatusRef.current)
    ) {
      refetch();
    }
    prevPollStatusRef.current = pollStatus;
  }, [statusData]); // eslint-disable-line react-hooks/exhaustive-deps

  async function handleStop() {
    setBusy(true);
    try { await apiPost(`/scans/${uuid}/stop/`); toast.success('Scan stopped.'); refetch(); }
    catch (e) { toast.error(e.message || 'Stop failed.'); }
    finally { setBusy(false); }
  }

  async function handleDelete() {
    setBusy(true);
    try { await apiPost(`/scans/${uuid}/delete/`); navigate('/scans'); }
    catch (e) { toast.error(e.message || 'Delete failed.'); setBusy(false); }
  }

  if (loading) return <Layout><div className="flex justify-center items-center h-64"><Spinner size={40} /></div></Layout>;
  if (error)   return <Layout><div className="text-red-400 p-4">Error: {error}</div></Layout>;
  if (!data)   return <Layout><div /></Layout>;

  const session     = data.session || {};
  const liveStatus  = statusData?.session?.status || session.status;
  const isRunning   = liveStatus === 'running';
  const assetCounts = statusData?.asset_counts || data.asset_counts || {};
  const vulnCounts  = statusData?.vuln_counts  || data.vuln_counts  || {};

  const subdomains = data.subdomains || [];
  const ips        = data.ips        || [];
  const ports      = data.ports      || [];
  const urls       = data.urls       || [];
  const findings   = [
    ...(data.nmap_findings    || []),
    ...(data.domain_findings  || []),
    ...(data.other_findings   || []),
  ].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
  });

  const tabData = { subdomains, ips, ports, urls, findings };
  const filteredUrls = urls.filter(u => {
    if (schemeFilter && u.scheme !== schemeFilter) return false;
    if (statusFilter && !String(u.status_code ?? '').startsWith(statusFilter)) return false;
    return true;
  });

  const items      = tab === 'urls' ? filteredUrls : (tabData[tab] || []);
  const paged      = items.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const totalPages = Math.ceil(items.length / PAGE_SIZE);

  return (
    <Layout>
      <div className="space-y-5">
        <div className="flex items-start justify-between flex-wrap gap-3">
          <div>
            <button onClick={() => navigate('/scans')} className="text-dim text-xs hover:text-body mb-1 block">← Scans</button>
            <h1 className="text-lit text-xl font-bold font-mono">{session.domain_name}</h1>
            <div className="flex items-center gap-2 mt-1 flex-wrap">
              <Badge value={liveStatus} />
              {isRunning && <Spinner size={14} />}
            </div>
            <p className="text-dim text-xs mt-1">
              Started: {fmtDate(session.start_time)}{session.end_time && <> · Finished: {fmtDate(session.end_time)}</>}
            </p>
          </div>
          <span className="inline-flex gap-1.5 items-center flex-wrap">
            {isRunning && <ConfirmButton label="Stop" confirmLabel="Stop scan?" onConfirm={handleStop} disabled={busy} />}
            {liveStatus === 'completed' && (<>
              <Button variant="outline" size="sm" asChild>
                <a href={`/reports/${uuid}/csv/?token=${auth.getToken()}`} download>CSV</a>
              </Button>
              <Button variant="outline" size="sm" asChild>
                <a href={`/reports/${uuid}/pdf/?token=${auth.getToken()}`} download>PDF</a>
              </Button>
            </>)}
            <ConfirmButton label="Delete" onConfirm={handleDelete} disabled={busy} />
          </span>
        </div>

        <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
          <StatCard label="Subdomains" value={assetCounts.subdomains_total} />
          <StatCard label="IPs"        value={assetCounts.ips} />
          <StatCard label="Ports"      value={assetCounts.ports} />
          <StatCard label="URLs"       value={assetCounts.urls} />
          <StatCard label="Critical"   value={vulnCounts.critical} danger />
          <StatCard label="Findings"   value={session.total_findings} />
        </div>

        <div>
          <div className="flex gap-0.5 border-b border-rim mb-4">
            {TABS.map(t => (
              <button key={t} onClick={() => { setTab(t); setPage(1); setSchemeFilter(''); setStatusFilter(''); }}
                className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors capitalize
                  ${t === tab ? 'border-brand text-brand' : 'border-transparent text-dim hover:text-body'}`}>
                {t} ({t === 'urls' ? filteredUrls.length : (tabData[t] || []).length})
              </button>
            ))}
          </div>

          <Card className="overflow-hidden">
            {tab === 'urls' && (
              <div className="flex gap-3 px-4 pt-4 pb-2 flex-wrap">
                <select value={schemeFilter} onChange={e => { setSchemeFilter(e.target.value); setPage(1); }} className="field w-32">
                  <option value="">All schemes</option>
                  <option value="https">https</option>
                  <option value="http">http</option>
                </select>
                <input type="text" inputMode="numeric" value={statusFilter}
                  onChange={e => { setStatusFilter(e.target.value.trim()); setPage(1); }}
                  placeholder="Status code…" className="field w-36" />
              </div>
            )}
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <Table>
                  {tab === 'subdomains' && <>
                    <TableHeader><TableRow>{['Subdomain', 'Active', 'Discovered'].map(h => <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>)}</TableRow></TableHeader>
                    <TableBody>
                      {paged.length === 0
                        ? <TableRow><TableCell colSpan={3} className="px-4 py-8 text-center text-dim">None found.</TableCell></TableRow>
                        : paged.map(s => (
                          <TableRow key={s.id} className="hover:bg-hover">
                            <TableCell className="px-4 py-3 font-mono text-lit">{s.subdomain}</TableCell>
                            <TableCell className="px-4 py-3"><Badge value={s.is_active ? 'active' : 'inactive'} /></TableCell>
                            <TableCell className="px-4 py-3 text-dim text-xs">{fmtDate(s.discovered_at)}</TableCell>
                          </TableRow>
                        ))}
                    </TableBody>
                  </>}
                  {tab === 'ips' && <>
                    <TableHeader><TableRow>{['IP', 'Version', 'Source'].map(h => <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>)}</TableRow></TableHeader>
                    <TableBody>
                      {paged.length === 0
                        ? <TableRow><TableCell colSpan={3} className="px-4 py-8 text-center text-dim">None found.</TableCell></TableRow>
                        : paged.map(ip => (
                          <TableRow key={ip.id} className="hover:bg-hover">
                            <TableCell className="px-4 py-3 font-mono text-lit">{ip.address}</TableCell>
                            <TableCell className="px-4 py-3 text-dim text-xs">v{ip.version}</TableCell>
                            <TableCell className="px-4 py-3 text-dim text-xs">{ip.source || '—'}</TableCell>
                          </TableRow>
                        ))}
                    </TableBody>
                  </>}
                  {tab === 'ports' && <>
                    <TableHeader><TableRow>{['Host', 'Port', 'Service', 'Version', 'Web?'].map(h => <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>)}</TableRow></TableHeader>
                    <TableBody>
                      {paged.length === 0
                        ? <TableRow><TableCell colSpan={5} className="px-4 py-8 text-center text-dim">None found.</TableCell></TableRow>
                        : paged.map(p => (
                          <TableRow key={p.id} className="hover:bg-hover">
                            <TableCell className="px-4 py-3 font-mono text-dim text-xs">{p.address}</TableCell>
                            <TableCell className="px-4 py-3 font-mono text-lit font-semibold">{p.port}/{p.protocol}</TableCell>
                            <TableCell className="px-4 py-3 text-dim">{p.service || '—'}</TableCell>
                            <TableCell className="px-4 py-3 text-dim text-xs">{p.version || '—'}</TableCell>
                            <TableCell className="px-4 py-3">{p.is_web ? <Badge value="web" /> : <span className="text-dim">—</span>}</TableCell>
                          </TableRow>
                        ))}
                    </TableBody>
                  </>}
                  {tab === 'urls' && <>
                    <TableHeader><TableRow>{['Scheme', 'URL', 'Status', 'Title', 'Server', 'Size'].map(h => <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>)}</TableRow></TableHeader>
                    <TableBody>
                      {paged.length === 0 ? (
                        <TableRow><TableCell colSpan={6} className="px-4 py-8 text-center text-dim">
                          {(schemeFilter || statusFilter) ? 'No URLs match the current filters.' : 'No URLs discovered yet.'}
                        </TableCell></TableRow>
                      ) : paged.map(u => (
                        <TableRow key={u.id} className="hover:bg-hover">
                          <TableCell className="px-4 py-3">
                            <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold uppercase ${SCHEME_CLS[u.scheme] ?? 'bg-gray-800/60 text-gray-400 border border-gray-700'}`}>
                              {u.scheme || '—'}
                            </span>
                          </TableCell>
                          <TableCell className="px-4 py-3 font-mono text-brand text-xs max-w-xs truncate">
                            <a href={u.url} target="_blank" rel="noopener noreferrer" className="hover:underline">{u.url}</a>
                          </TableCell>
                          <TableCell className={`px-4 py-3 font-mono font-semibold ${statusColor(u.status_code)}`}>{u.status_code || '—'}</TableCell>
                          <TableCell className="px-4 py-3 text-body text-xs max-w-xs truncate">{u.title || '—'}</TableCell>
                          <TableCell className="px-4 py-3 text-dim text-xs">{u.web_server || '—'}</TableCell>
                          <TableCell className="px-4 py-3 text-dim text-xs">{fmtSize(u.content_length)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </>}
                  {tab === 'findings' && <>
                    <TableHeader><TableRow>{['Sev', 'Title', 'Target', 'Source'].map(h => <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>)}</TableRow></TableHeader>
                    <TableBody>
                      {paged.length === 0
                        ? <TableRow><TableCell colSpan={4} className="px-4 py-8 text-center text-dim">None found.</TableCell></TableRow>
                        : paged.map(f => (
                          <TableRow key={f.id} className="hover:bg-hover">
                            <TableCell className="px-4 py-3"><Badge value={f.severity} /></TableCell>
                            <TableCell className="px-4 py-3 text-body font-medium max-w-xs truncate">{f.title}</TableCell>
                            <TableCell className="px-4 py-3 font-mono text-dim text-xs">{f.target}</TableCell>
                            <TableCell className="px-4 py-3 text-dim text-xs">{f.source}</TableCell>
                          </TableRow>
                        ))}
                    </TableBody>
                  </>}
                </Table>
              </div>
            </CardContent>
            {totalPages > 1 && (
              <div className="px-4 py-3 border-t border-border">
                <Pagination page={page} totalPages={totalPages} onPage={setPage} />
              </div>
            )}
          </Card>
        </div>
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd frontend && git add src/pages/ScanDetailPage.jsx
git commit -m "feat(frontend): migrate ScanDetailPage to shadcn Card, Table, Button, toast"
```

---

### Task 17: Update ScanStartPage.jsx

**Files:**
- Modify: `frontend/src/pages/ScanStartPage.jsx`

- [ ] **Step 1: Replace ScanStartPage.jsx**

```jsx
import React, { useState, useEffect } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
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
      const body = { domain, schedule_type: scheduled ? 'once' : 'now' };
      if (workflowId) body.workflow_id = Number(workflowId);
      if (scheduled && schedTime) body.scheduled_at = schedTime;
      await apiPost('/scans/start/', body);
      navigate('/scans');
    } catch (err) {
      setError(err.data?.error?.message || err.message || 'Failed to start scan.');
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
          <Card>
            <CardHeader className="border-b border-border px-6 py-4">
              <CardTitle className="text-sm font-semibold">Scan Configuration</CardTitle>
            </CardHeader>
            <CardContent className="px-6 py-5">
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-xs text-dim mb-1 font-medium">Domain *</label>
                  <select value={domain} onChange={e => setDomain(e.target.value)} required className="field">
                    <option value="">— select domain —</option>
                    {domains.filter(d => d.is_active).map(d => (
                      <option key={d.id} value={d.name}>{d.name}</option>
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
                  <Button type="submit" disabled={submitting}>
                    {submitting ? 'Starting…' : scheduled ? 'Schedule Scan' : 'Start Scan Now'}
                  </Button>
                  <Button type="button" variant="outline" onClick={() => navigate('/scans')}>Cancel</Button>
                </div>
              </form>
            </CardContent>
          </Card>
        )}
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd frontend && git add src/pages/ScanStartPage.jsx
git commit -m "feat(frontend): migrate ScanStartPage to shadcn Card, Button"
```

---

### Task 18: Update WorkflowsPage.jsx

**Files:**
- Modify: `frontend/src/pages/WorkflowsPage.jsx`

- [ ] **Step 1: Replace WorkflowsPage.jsx**

```jsx
import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { ConfirmButton } from '../components/ConfirmButton.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import { toast } from '../components/Notification.jsx';
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
      onCreated(res);
      setName(''); setDesc(''); setDef(false); setSel([]);
    } catch (e) { setErr(e.message); }
    finally { setSaving(false); }
  }

  return (
    <Card className="mb-5">
      <CardHeader className="border-b border-border px-5 py-4">
        <CardTitle className="text-sm font-semibold">Create Workflow</CardTitle>
      </CardHeader>
      <CardContent className="px-5 py-5">
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
          <Button type="submit" disabled={saving}>{saving ? 'Creating…' : 'Create Workflow'}</Button>
        </form>
      </CardContent>
    </Card>
  );
}

export default function WorkflowsPage() {
  const { data, loading, error, refetch } = useFetch('/workflows/');
  const [busyIds, setBusyIds] = useState(new Set());

  const workflows = data || [];
  function busy(id) { return busyIds.has(id); }
  function setBusy(id, val) {
    setBusyIds(s => { const ns = new Set(s); val ? ns.add(id) : ns.delete(id); return ns; });
  }

  async function handleDelete(id, name) {
    setBusy(id, true);
    try { await apiPost(`/workflows/${id}/delete/`); toast.success(`"${name}" deleted.`); refetch(); }
    catch (e) { toast.error(e.message || 'Delete failed.'); }
    finally { setBusy(id, false); }
  }

  return (
    <Layout>
      <div className="space-y-5">
        <div>
          <h1 className="text-lit text-xl font-bold">Workflows</h1>
          <p className="text-dim text-sm mt-0.5">Manage scan workflows and tool configurations</p>
        </div>
        <CreateWorkflowForm onCreated={() => { toast.success('Workflow created.'); refetch(); }} />
        <Card className="overflow-hidden">
          {loading ? <div className="flex justify-center p-8"><Spinner /></div>
          : error   ? <div className="p-6 text-red-400 text-sm">Error: {error}</div>
          : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    {['Name', 'Default?', 'Tools', 'Description', 'Actions'].map(h => (
                      <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {workflows.length === 0 ? (
                    <TableRow><TableCell colSpan={5} className="px-4 py-10 text-center text-dim">No workflows yet.</TableCell></TableRow>
                  ) : workflows.map(wf => (
                    <TableRow key={wf.id} className={`hover:bg-hover transition-colors ${busy(wf.id) ? 'opacity-50' : ''}`}>
                      <TableCell className="px-4 py-3 text-lit font-medium">{wf.name}</TableCell>
                      <TableCell className="px-4 py-3">
                        {wf.is_default
                          ? <span className="text-brand text-xs font-semibold">Default</span>
                          : <span className="text-dim text-xs">—</span>}
                      </TableCell>
                      <TableCell className="px-4 py-3 text-dim">{wf.steps ? wf.steps.filter(s => s.enabled !== false).length : '—'}</TableCell>
                      <TableCell className="px-4 py-3 text-dim max-w-xs truncate">{wf.description || '—'}</TableCell>
                      <TableCell className="px-4 py-3">
                        <span className="inline-flex gap-1.5 items-center">
                          <Button variant="outline" size="sm" onClick={() => navigate(`/workflows/${wf.id}`)}>View</Button>
                          <ConfirmButton label="Delete" disabled={busy(wf.id)} onConfirm={() => handleDelete(wf.id, wf.name)} />
                        </span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </Card>
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd frontend && git add src/pages/WorkflowsPage.jsx
git commit -m "feat(frontend): migrate WorkflowsPage to shadcn Card, Table, Button, toast"
```

---

### Task 19: Update WorkflowDetailPage.jsx

**Files:**
- Modify: `frontend/src/pages/WorkflowDetailPage.jsx`

- [ ] **Step 1: Replace WorkflowDetailPage.jsx**

```jsx
import React, { useState, useEffect } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import { toast } from '../components/Notification.jsx';
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
  const [name,     setName]    = useState('');
  const [desc,     setDesc]    = useState('');
  const [saving,   setSaving]  = useState(false);
  const [toggling, setToggling] = useState(null);

  useEffect(() => {
    if (data?.workflow) { setName(data.workflow.name || ''); setDesc(data.workflow.description || ''); }
  }, [data]);

  async function handleSave(e) {
    e.preventDefault(); setSaving(true);
    try { await apiPost(`/workflows/${id}/update/`, { name: name.trim(), description: desc.trim() }); toast.success('Updated.'); refetch(); }
    catch (e) { toast.error(e.message || 'Update failed.'); }
    finally { setSaving(false); }
  }

  async function handleToggle(tool) {
    setToggling(tool);
    try { await apiPost(`/workflows/${id}/steps/${tool}/toggle/`); refetch(); }
    catch (e) { toast.error(e.message || 'Toggle failed.'); }
    finally { setToggling(null); }
  }

  if (loading) return <Layout><div className="flex justify-center items-center h-64"><Spinner size={40} /></div></Layout>;
  if (error)   return <Layout><div className="text-red-400 p-4">Error: {error}</div></Layout>;
  if (!data)   return <Layout><div /></Layout>;

  const workflow    = data.workflow    || {};
  const steps       = data.tool_steps  || [];
  const recent_runs = data.recent_runs || [];

  return (
    <Layout>
      <div className="space-y-6 max-w-3xl">
        <div>
          <button onClick={() => navigate('/workflows')} className="text-dim text-xs hover:text-body mb-1 block">← Workflows</button>
          <h1 className="text-lit text-xl font-bold">{workflow.name}</h1>
          {workflow.is_default && <span className="text-brand text-xs font-semibold">Default workflow</span>}
        </div>

        <Card>
          <CardHeader className="border-b border-border px-5 py-4">
            <CardTitle className="text-sm font-semibold">Edit</CardTitle>
          </CardHeader>
          <CardContent className="px-5 py-5">
            <form onSubmit={handleSave} className="space-y-3">
              <div>
                <label className="block text-xs text-dim mb-1">Name</label>
                <input value={name} onChange={e => setName(e.target.value)} className="field" />
              </div>
              <div>
                <label className="block text-xs text-dim mb-1">Description</label>
                <input value={desc} onChange={e => setDesc(e.target.value)} className="field" />
              </div>
              <Button type="submit" disabled={saving}>{saving ? 'Saving…' : 'Save'}</Button>
            </form>
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader className="border-b border-border px-4 py-3">
            <CardTitle className="text-sm font-semibold">Tool Steps</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    {['Phase', 'Tool', 'Status', 'Toggle'].map(h => (
                      <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {steps.length === 0 ? (
                    <TableRow><TableCell colSpan={4} className="px-4 py-8 text-center text-dim">No steps.</TableCell></TableRow>
                  ) : steps.map(s => (
                    <TableRow key={s.key} className="hover:bg-hover transition-colors">
                      <TableCell className="px-4 py-3 text-dim text-xs">{s.phase ?? s.key}</TableCell>
                      <TableCell className="px-4 py-3 text-lit font-medium">{s.label || s.key}</TableCell>
                      <TableCell className="px-4 py-3"><Badge value={s.enabled !== false ? 'active' : 'inactive'} /></TableCell>
                      <TableCell className="px-4 py-3">
                        <Button variant="outline" size="sm" onClick={() => handleToggle(s.key)} disabled={toggling === s.key}>
                          {toggling === s.key ? '…' : s.enabled !== false ? 'Disable' : 'Enable'}
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {recent_runs.length > 0 && (
          <Card className="overflow-hidden">
            <CardHeader className="border-b border-border px-4 py-3">
              <CardTitle className="text-sm font-semibold">Recent Runs</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      {['Scan', 'Status', 'Started', 'Finished'].map(h => (
                        <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {recent_runs.map(r => (
                      <TableRow key={r.id} className="hover:bg-hover transition-colors">
                        <TableCell className="px-4 py-3 font-mono text-lit">
                          {r.session_uuid
                            ? <button onClick={() => navigate(`/scans/${r.session_uuid}`)} className="text-brand hover:underline font-mono text-xs">{r.session_uuid.slice(0, 8)}…</button>
                            : '—'}
                        </TableCell>
                        <TableCell className="px-4 py-3"><Badge value={r.status} /></TableCell>
                        <TableCell className="px-4 py-3 text-dim">{fmtDate(r.started_at)}</TableCell>
                        <TableCell className="px-4 py-3 text-dim">{fmtDate(r.finished_at)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd frontend && git add src/pages/WorkflowDetailPage.jsx
git commit -m "feat(frontend): migrate WorkflowDetailPage to shadcn Card, Table, Button, toast"
```

---

### Task 20: Update InsightsPage.jsx

**Files:**
- Modify: `frontend/src/pages/InsightsPage.jsx`

- [ ] **Step 1: Replace InsightsPage.jsx**

```jsx
import React from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
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
    <Card className="overflow-hidden mb-5">
      {(title || subtitle) && (
        <CardHeader className="border-b border-border px-4 py-3">
          {title    && <CardTitle className="text-sm font-semibold">{title}</CardTitle>}
          {subtitle && <p className="text-dim text-xs mt-0.5">{subtitle}</p>}
        </CardHeader>
      )}
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                {columns.map(c => (
                  <TableHead key={c} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{c}</TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows && rows.length > 0
                ? rows.map((row, i) => <TableRow key={i} className="hover:bg-hover transition-colors">{renderRow(row, i)}</TableRow>)
                : <TableRow><TableCell colSpan={columns.length} className="px-4 py-8 text-center text-dim">{emptyMsg}</TableCell></TableRow>}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
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
                <TableCell className="px-4 py-3"><Badge value={sev} /></TableCell>
                <TableCell className={`px-4 py-3 font-semibold ${SEV_TEXT[sev] || 'text-body'}`}>{cnt}</TableCell>
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
              <TableCell className="px-4 py-3 text-lit font-medium">{row.label || '—'}</TableCell>
              <TableCell className={`px-4 py-3 ${row.critical > 0 ? 'text-red-400 font-semibold' : 'text-dim'}`}>{row.critical ?? 0}</TableCell>
              <TableCell className={`px-4 py-3 ${row.high > 0 ? 'text-orange-400 font-semibold' : 'text-dim'}`}>{row.high ?? 0}</TableCell>
              <TableCell className={`px-4 py-3 ${row.medium > 0 ? 'text-yellow-400 font-semibold' : 'text-dim'}`}>{row.medium ?? 0}</TableCell>
              <TableCell className={`px-4 py-3 ${row.low > 0 ? 'text-blue-400 font-semibold' : 'text-dim'}`}>{row.low ?? 0}</TableCell>
              <TableCell className="px-4 py-3 text-body font-semibold">{row.total ?? 0}</TableCell>
            </>
          )}
        />

        <DataTable
          title="Delta Trend" subtitle="New vs. removed findings per scan"
          columns={['Scan', 'New Findings', 'Removed Findings']}
          rows={delta_trend} emptyMsg="No delta data yet."
          renderRow={row => (
            <>
              <TableCell className="px-4 py-3 text-lit font-medium">{row.label || '—'}</TableCell>
              <TableCell className={`px-4 py-3 ${row.new > 0 ? 'text-red-400 font-semibold' : 'text-dim'}`}>{row.new ?? 0}</TableCell>
              <TableCell className={`px-4 py-3 ${row.removed > 0 ? 'text-brand font-semibold' : 'text-dim'}`}>{row.removed ?? 0}</TableCell>
            </>
          )}
        />

        <DataTable
          title="Top Hosts by Findings"
          columns={['Domain', 'Finding Count']} rows={top_hosts} emptyMsg="No host data."
          renderRow={row => (
            <>
              <TableCell className="px-4 py-3 font-mono text-lit font-medium">{row.domain}</TableCell>
              <TableCell className="px-4 py-3 text-brand font-semibold">{row.count}</TableCell>
            </>
          )}
        />

        <DataTable
          title="Top Finding Types"
          columns={['Severity', 'Title', 'Check Type', 'Occurrences', 'Last Seen']}
          rows={top_finding_types} emptyMsg="No finding type data."
          renderRow={row => (
            <>
              <TableCell className="px-4 py-3"><Badge value={row.severity} /></TableCell>
              <TableCell className="px-4 py-3 text-lit font-medium max-w-xs truncate">{row.title}</TableCell>
              <TableCell className="px-4 py-3 font-mono text-dim text-xs">{row.check_type || '—'}</TableCell>
              <TableCell className="px-4 py-3 text-brand font-semibold">{row.occurrence_count}</TableCell>
              <TableCell className="px-4 py-3 text-dim text-xs">{fmtDate(row.last_seen)}</TableCell>
            </>
          )}
        />

        {top_services.length > 0 && (
          <DataTable
            title="Top Services (CVEs)"
            columns={['Service', 'Version', 'CVE Count', 'Max CVSS']} rows={top_services}
            renderRow={row => (
              <>
                <TableCell className="px-4 py-3 font-mono text-lit font-medium">{row.service || '—'}</TableCell>
                <TableCell className="px-4 py-3 font-mono text-dim text-xs">{row.version || '—'}</TableCell>
                <TableCell className={`px-4 py-3 ${row.cve_count > 0 ? 'text-red-400 font-semibold' : 'text-dim'}`}>{row.cve_count ?? 0}</TableCell>
                <TableCell className={`px-4 py-3 font-semibold ${row.max_cvss >= 7 ? 'text-red-400' : row.max_cvss >= 4 ? 'text-yellow-400' : 'text-dim'}`}>
                  {row.max_cvss != null ? row.max_cvss.toFixed(1) : '—'}
                </TableCell>
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
                <TableCell className="px-4 py-3 text-lit font-medium">{row.label || '—'}</TableCell>
                <TableCell className="px-4 py-3 text-body">{row.subdomains ?? 0}</TableCell>
                <TableCell className="px-4 py-3 text-brand">{row.active_subdomains ?? 0}</TableCell>
                <TableCell className="px-4 py-3 text-body">{row.ips ?? 0}</TableCell>
                <TableCell className="px-4 py-3 text-body">{row.ports ?? 0}</TableCell>
                <TableCell className="px-4 py-3 text-body">{row.urls ?? 0}</TableCell>
              </>
            )}
          />
        )}
      </div>
    </Layout>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd frontend && git add src/pages/InsightsPage.jsx
git commit -m "feat(frontend): migrate InsightsPage to shadcn Card, Table"
```

---

### Task 21: Clean up index.css and verify build

**Files:**
- Modify: `frontend/src/index.css`

Remove all now-unused CSS class definitions: `.btn-primary`, `.btn-ghost`, `.btn-danger`, `.tbl-th`, `.tbl-td`, and all `.badge-*` classes. Keep `.field` (used for `<input>` and `<select>` elements which are not replaced by shadcn).

- [ ] **Step 1: Replace index.css with cleaned version**

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  :root {
    --background: 215 28% 7%;
    --foreground: 210 26% 93%;
    --card: 214 22% 11%;
    --card-foreground: 210 26% 93%;
    --popover: 214 22% 11%;
    --popover-foreground: 210 26% 93%;
    --primary: 145 60% 47%;
    --primary-foreground: 215 28% 7%;
    --secondary: 214 18% 13%;
    --secondary-foreground: 210 17% 82%;
    --muted: 214 18% 13%;
    --muted-foreground: 211 8% 58%;
    --accent: 214 18% 13%;
    --accent-foreground: 210 17% 82%;
    --destructive: 0 72% 51%;
    --destructive-foreground: 0 0% 98%;
    --border: 210 12% 21%;
    --input: 210 12% 21%;
    --ring: 145 60% 47%;
    --radius: 0.5rem;
  }
}

@layer components {
  /* Form inputs and selects (not replaced by shadcn) */
  .field {
    @apply w-full bg-canvas border border-rim rounded-md px-3 py-2 text-sm text-body placeholder-dim focus:outline-none focus:border-brand transition-colors;
  }
}
```

- [ ] **Step 2: Run build to verify no errors**

```bash
cd frontend && npm run build
```

Expected: build completes with exit 0 and outputs to `frontend/dist/`. If there are import errors (e.g., missing component files from shadcn CLI), re-run the affected `npx shadcn@latest add <component>` command.

- [ ] **Step 3: Final commit**

```bash
cd frontend && git add src/index.css
git commit -m "feat(frontend): clean up index.css, remove replaced CSS classes"
```
