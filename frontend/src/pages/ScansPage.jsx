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
