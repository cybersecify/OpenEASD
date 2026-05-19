import React, { useState, useEffect } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { toast } from '../components/Notification.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
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
  const [name,  setName]  = useState('');
  const [desc,  setDesc]  = useState('');
  const [saving, setSaving] = useState(false);
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

        {/* Edit form */}
        <Card>
          <CardHeader className="border-b border-border px-4 py-3">
            <CardTitle className="text-sm font-semibold">Edit</CardTitle>
          </CardHeader>
          <CardContent className="p-5">
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

        {/* Tool steps */}
        <Card className="overflow-hidden">
          <CardHeader className="border-b border-border px-4 py-3">
            <CardTitle className="text-sm font-semibold">Tool Steps</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>{['Phase', 'Tool', 'Status', 'Toggle'].map(h => <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>)}</TableRow>
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
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleToggle(s.key)}
                          disabled={toggling === s.key}
                        >
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

        {/* Recent runs */}
        {recent_runs.length > 0 && (
          <Card className="overflow-hidden">
            <CardHeader className="border-b border-border px-4 py-3">
              <CardTitle className="text-sm font-semibold">Recent Runs</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>{['Scan', 'Status', 'Started', 'Finished'].map(h => <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>)}</TableRow>
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
