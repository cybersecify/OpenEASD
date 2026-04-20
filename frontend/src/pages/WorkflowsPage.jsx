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
      onCreated(res);
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
