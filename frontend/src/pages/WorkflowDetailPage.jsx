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
