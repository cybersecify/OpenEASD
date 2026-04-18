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
