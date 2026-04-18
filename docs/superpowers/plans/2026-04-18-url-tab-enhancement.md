# URL Tab Enhancement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enhance the `urls` tab in `ScanDetailPage.jsx` to show all httpx fields with scheme/status-code filtering.

**Architecture:** Single file change — add three helper functions and a `SCHEME_CLS` map above the component, add two `useState` filter values inside the component, compute a `filteredUrls` array client-side, wire filter resets into the tab-change handler, render filter controls above the table, and replace the 4-column URL table with a 6-column one.

**Tech Stack:** React 18, Vite dev server, Tailwind CSS (dark theme utility classes)

---

## File Map

| Action | File |
|---|---|
| Modify | `frontend/src/pages/ScanDetailPage.jsx` |

---

### Task 1: Add helper functions and scheme style map

**Files:**
- Modify: `frontend/src/pages/ScanDetailPage.jsx` (after `fmtDate`, before `StatCard`)

- [ ] **Step 1: Add `fmtSize`, `statusColor`, and `SCHEME_CLS` after the existing `fmtDate` function (line 20)**

  In `frontend/src/pages/ScanDetailPage.jsx`, insert after the closing brace of `fmtDate` (after line 20) and before `function StatCard`:

  ```js
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
  ```

- [ ] **Step 2: Verify the file parses — run the Vite dev server**

  ```bash
  cd frontend && npm run dev
  ```
  Expected: server starts on port 5173 with no compilation errors. Stop it with Ctrl+C.

- [ ] **Step 3: Commit**

  ```bash
  git add frontend/src/pages/ScanDetailPage.jsx
  git commit -m "feat: add fmtSize, statusColor, SCHEME_CLS helpers for URL tab"
  ```

---

### Task 2: Add filter state and filtered items logic

**Files:**
- Modify: `frontend/src/pages/ScanDetailPage.jsx` (inside `ScanDetailPage` component)

- [ ] **Step 1: Add two filter state variables inside the component**

  In `ScanDetailPage`, the current state declarations are at lines 33–36:
  ```js
  const [tab,  setTab]  = useState('subdomains');
  const [page, setPage] = useState(1);
  const [notification, setNotification] = useState(null);
  const [busy, setBusy] = useState(false);
  ```

  Add two new lines immediately after them:
  ```js
  const [schemeFilter, setSchemeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  ```

- [ ] **Step 2: Compute `filteredUrls` and update the `items` derivation**

  The current pagination logic (around line 84–87) reads:
  ```js
  const tabData  = { subdomains, ips, ports, urls, findings };
  const items    = tabData[tab] || [];
  const paged    = items.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const totalPages = Math.ceil(items.length / PAGE_SIZE);
  ```

  Replace those four lines with:
  ```js
  const tabData = { subdomains, ips, ports, urls, findings };

  const filteredUrls = urls.filter(u => {
    if (schemeFilter && u.scheme !== schemeFilter) return false;
    if (statusFilter && !String(u.status_code ?? '').startsWith(statusFilter)) return false;
    return true;
  });

  const items      = tab === 'urls' ? filteredUrls : (tabData[tab] || []);
  const paged      = items.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const totalPages = Math.ceil(items.length / PAGE_SIZE);
  ```

- [ ] **Step 3: Verify Vite compiles cleanly**

  ```bash
  cd frontend && npm run dev
  ```
  Expected: starts with no errors. Stop with Ctrl+C.

- [ ] **Step 4: Commit**

  ```bash
  git add frontend/src/pages/ScanDetailPage.jsx
  git commit -m "feat: add scheme/status filter state and filteredUrls derivation"
  ```

---

### Task 3: Reset filters when switching tabs

**Files:**
- Modify: `frontend/src/pages/ScanDetailPage.jsx` (tab button `onClick`)

- [ ] **Step 1: Find the tab button `onClick` handler**

  Currently the tab buttons (around line 127) use an inline handler:
  ```jsx
  onClick={() => { setTab(t); setPage(1); }}
  ```

- [ ] **Step 2: Extend the handler to reset filters**

  Replace that inline handler with:
  ```jsx
  onClick={() => {
    setTab(t);
    setPage(1);
    setSchemeFilter('');
    setStatusFilter('');
  }}
  ```

- [ ] **Step 3: Commit**

  ```bash
  git add frontend/src/pages/ScanDetailPage.jsx
  git commit -m "feat: reset URL filters on tab change"
  ```

---

### Task 4: Render filter controls and the enhanced URL table

**Files:**
- Modify: `frontend/src/pages/ScanDetailPage.jsx` (urls tab block, lines 182–198)

- [ ] **Step 1: Locate the current urls tab block**

  It currently looks like (lines 182–198):
  ```jsx
  {tab === 'urls' && <>
    <thead><tr>{['URL', 'Status', 'Title', 'Server'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr></thead>
    <tbody>
      {paged.length === 0
        ? <tr><td colSpan={4} className="tbl-td text-center text-dim py-8">None found.</td></tr>
        : paged.map(u => (
          <tr key={u.id} className="hover:bg-hover">
            <td className="tbl-td font-mono text-brand text-xs max-w-xs truncate">
              <a href={u.url} target="_blank" rel="noopener noreferrer" className="hover:underline">{u.url}</a>
            </td>
            <td className="tbl-td text-dim">{u.status_code || '—'}</td>
            <td className="tbl-td text-body text-xs max-w-xs truncate">{u.title || '—'}</td>
            <td className="tbl-td text-dim text-xs">{u.web_server || '—'}</td>
          </tr>
        ))}
    </tbody>
  </>}
  ```

- [ ] **Step 2: Add the filter bar above the table**

  The filter bar must be rendered *outside* the `<table>` element (the table is inside `<div className="overflow-x-auto">`). Insert it just before the `<div className="overflow-x-auto">` block, conditionally when `tab === 'urls'`:

  ```jsx
  {tab === 'urls' && (
    <div className="flex gap-3 px-4 pt-4 pb-2 flex-wrap">
      <select
        value={schemeFilter}
        onChange={e => { setSchemeFilter(e.target.value); setPage(1); }}
        className="field w-32"
      >
        <option value="">All schemes</option>
        <option value="https">https</option>
        <option value="http">http</option>
      </select>
      <input
        type="text"
        value={statusFilter}
        onChange={e => { setStatusFilter(e.target.value); setPage(1); }}
        placeholder="Status code…"
        className="field w-36"
      />
    </div>
  )}
  ```

- [ ] **Step 3: Replace the urls tab block with the 6-column version**

  Replace the entire `{tab === 'urls' && <> ... </>}` block (identified in Step 1) with:

  ```jsx
  {tab === 'urls' && <>
    <thead>
      <tr>
        {['Scheme', 'URL', 'Status', 'Title', 'Server', 'Size'].map(h =>
          <th key={h} className="tbl-th">{h}</th>
        )}
      </tr>
    </thead>
    <tbody>
      {paged.length === 0 ? (
        <tr>
          <td colSpan={6} className="tbl-td text-center text-dim py-8">
            {(schemeFilter || statusFilter) ? 'No URLs match the current filters.' : 'No URLs discovered yet.'}
          </td>
        </tr>
      ) : paged.map(u => (
        <tr key={u.id} className="hover:bg-hover">
          <td className="tbl-td">
            <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold uppercase ${SCHEME_CLS[u.scheme] ?? 'bg-gray-800/60 text-gray-400 border border-gray-700'}`}>
              {u.scheme || '—'}
            </span>
          </td>
          <td className="tbl-td font-mono text-brand text-xs max-w-xs truncate">
            <a href={u.url} target="_blank" rel="noopener noreferrer" className="hover:underline">{u.url}</a>
          </td>
          <td className={`tbl-td font-mono font-semibold ${statusColor(u.status_code)}`}>
            {u.status_code || '—'}
          </td>
          <td className="tbl-td text-body text-xs max-w-xs truncate">{u.title || '—'}</td>
          <td className="tbl-td text-dim text-xs">{u.web_server || '—'}</td>
          <td className="tbl-td text-dim text-xs">{fmtSize(u.content_length)}</td>
        </tr>
      ))}
    </tbody>
  </>}
  ```

- [ ] **Step 4: Verify Vite compiles cleanly**

  ```bash
  cd frontend && npm run dev
  ```
  Expected: starts on port 5173 with no compilation errors.

- [ ] **Step 5: Manual smoke test in browser**

  - Navigate to `http://localhost:5173` (requires Django running on 8000)
  - Open any completed scan → click the **urls** tab
  - Confirm 6 columns render: Scheme (badge), URL (link), Status (coloured), Title, Server, Size
  - Test scheme filter: select `https` → only https rows shown
  - Test status filter: type `2` → only 2xx rows shown; type `200` → only 200 rows
  - Switch to another tab → filters reset; switch back → filters are empty
  - Confirm empty state message differs when filters are active vs inactive

- [ ] **Step 6: Commit**

  ```bash
  git add frontend/src/pages/ScanDetailPage.jsx
  git commit -m "feat: enhance URLs tab with 6 columns and scheme/status filters"
  ```

---

### Task 5: Build and verify production bundle

**Files:**
- No file changes — build verification only

- [ ] **Step 1: Build the frontend**

  ```bash
  cd frontend && npm run build
  ```
  Expected: `frontend/dist/` updated with no errors or warnings about the changed file.

- [ ] **Step 2: Run Django tests to confirm no backend regressions**

  ```bash
  uv run pytest tests/ --ignore=tests/unit/test_domain_security.py -q
  ```
  Expected: all tests pass (exit 0).

- [ ] **Step 3: Final commit**

  ```bash
  cd frontend && npm run build
  git add frontend/dist
  git commit -m "build: update frontend dist for URL tab enhancement"
  ```
