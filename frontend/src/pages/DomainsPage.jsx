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
