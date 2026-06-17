import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { ConfirmButton } from '../components/ConfirmButton.jsx';
import { toast } from '../components/Notification.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { apiPost, apiGet } from '../api/client.js';

function CreateWorkflowForm({ onCreated }) {
  const [name,     setName]    = useState('');
  const [desc,     setDesc]    = useState('');
  const [isDef,    setDef]     = useState(false);
  const [selected, setSel]     = useState([]);
  const [saving,   setSaving]  = useState(false);
  const [err,      setErr]     = useState(null);

  const { data: toolsData } = useQuery({
    queryKey: ['/workflows/tools/'],
    queryFn: () => apiGet('/workflows/tools/'),
  });
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
      <CardContent className="p-5">
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
          <Button type="submit" disabled={saving}>{saving ? 'Creating…' : 'Create Workflow'}</Button>
        </form>
      </CardContent>
    </Card>
  );
}

export default function WorkflowsPage() {
  const navigate = useNavigate();
  const { data, isLoading: loading, error, refetch } = useQuery({
    queryKey: ['/workflows/'],
    queryFn: () => apiGet('/workflows/'),
  });
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
                  <TableRow>{['Name', 'Default?', 'Tools', 'Description', 'Actions'].map(h => <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>)}</TableRow>
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
