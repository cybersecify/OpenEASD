import React from 'react';
import { navigate } from '../App.jsx';
import { useFetch } from '../hooks/useFetch.js';
import { apiPost } from '../api/client.js';
import { auth } from '../auth.js';

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
            onClick={async () => {
              try { await apiPost('/auth/logout/', { refresh: auth.getRefresh() }); } catch (_) {}
              auth.clear();
              navigate('/login');
            }}
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
