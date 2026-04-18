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
