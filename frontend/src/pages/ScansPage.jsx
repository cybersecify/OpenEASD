import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Pagination } from '../components/Pagination.jsx';
import { ConfirmButton } from '../components/ConfirmButton.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import { toast } from '../components/Notification.jsx';
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
  const [busyIds, setBusyIds] = useState(new Set());

  const { data: domainsData } = useFetch('/domains/');
  const { data: scansData, pagination, loading, error, refetch } = useFetch(
    `/scans/?domain=${domain}&status=${status}&page=${page}`,
    [domain, status, page],
  );
  const { data: scheduledData, refetch: refetchScheduled } = useFetch('/scheduled/');

  const scans     = scansData?.results ?? [];
  const scheduled = scheduledData || [];
  const domains   = domainsData || [];

  function busy(id) { return busyIds.has(id); }
  function setBusy(id, val) {
    setBusyIds(s => { const ns = new Set(s); val ? ns.add(id) : ns.delete(id); return ns; });
  }

  async function handleStop(uuid) {
    setBusy(uuid, true);
    try { await apiPost(`/scans/${uuid}/stop/`); toast.success('Scan stopped.'); refetch(); }
    catch (e) { toast.error(e.message || 'Stop failed.'); }
    finally { setBusy(uuid, false); }
  }

  async function handleDelete(uuid) {
    setBusy(uuid, true);
    try { await apiPost(`/scans/${uuid}/delete/`); toast.success('Scan deleted.'); refetch(); }
    catch (e) { toast.error(e.message || 'Delete failed.'); }
    finally { setBusy(uuid, false); }
  }

  async function handleCancelJob(jobId) {
    try { await apiPost(`/scheduled/${jobId}/cancel/`); toast.success('Job cancelled.'); refetchScheduled(); }
    catch (e) { toast.error(e.message || 'Cancel failed.'); }
  }

  return (
    <Layout>
      <div className="space-y-5">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h1 className="text-lit text-xl font-bold">Scans</h1>
            <p className="text-dim text-sm mt-0.5">Scan history and scheduled jobs</p>
          </div>
          <Button onClick={() => navigate('/scans/start')}>+ New Scan</Button>
        </div>

        <div className="flex gap-3 flex-wrap">
          <select value={domain} onChange={e => { setDomain(e.target.value); setPage(1); }} className="field w-52">
            <option value="">All domains</option>
            {domains.map(d => <option key={d.id} value={d.name}>{d.name}</option>)}
          </select>
          <select value={status} onChange={e => { setStatus(e.target.value); setPage(1); }} className="field w-40">
            <option value="">All statuses</option>
            {['pending', 'running', 'completed', 'failed', 'cancelled'].map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>

        <Card className="overflow-hidden">
          <CardHeader className="border-b border-border px-4 py-3">
            <CardTitle className="text-sm font-semibold">Scan Sessions</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? <div className="flex justify-center p-8"><Spinner /></div>
            : error   ? <div className="p-6 text-red-400 text-sm">Error: {error}</div>
            : (
              <>
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        {['Domain', 'Status', 'Started', 'Findings', 'Actions'].map(h => (
                          <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                        ))}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {scans.length === 0 ? (
                        <TableRow><TableCell colSpan={5} className="px-4 py-10 text-center text-dim">No scans yet.</TableCell></TableRow>
                      ) : scans.map(s => (
                        <TableRow key={s.uuid} className={`hover:bg-hover transition-colors ${busy(s.uuid) ? 'opacity-50' : ''}`}>
                          <TableCell className="px-4 py-3 text-lit font-mono font-medium">{s.domain_name || '—'}</TableCell>
                          <TableCell className="px-4 py-3"><Badge value={s.status} /></TableCell>
                          <TableCell className="px-4 py-3 text-dim">{fmtDate(s.start_time)}</TableCell>
                          <TableCell className="px-4 py-3 text-body">{s.total_findings ?? '—'}</TableCell>
                          <TableCell className="px-4 py-3">
                            <span className="inline-flex gap-1.5 items-center flex-wrap">
                              <Button variant="outline" size="sm" onClick={() => navigate(`/scans/${s.uuid}`)}>View</Button>
                              {s.status === 'running' && (
                                <ConfirmButton label="Stop" confirmLabel="Stop scan?" onConfirm={() => handleStop(s.uuid)} disabled={busy(s.uuid)} />
                              )}
                              {['completed', 'failed', 'cancelled'].includes(s.status) && (
                                <ConfirmButton label="Delete" onConfirm={() => handleDelete(s.uuid)} disabled={busy(s.uuid)} />
                              )}
                            </span>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
                {pagination && (
                  <div className="px-4 py-3 border-t border-border">
                    <Pagination page={pagination.page} totalPages={pagination.total_pages} onPage={setPage} />
                  </div>
                )}
              </>
            )}
          </CardContent>
        </Card>

        {scheduled.length > 0 && (
          <Card className="overflow-hidden">
            <CardHeader className="border-b border-border px-4 py-3">
              <CardTitle className="text-sm font-semibold">Scheduled Jobs</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      {['Domain', 'Type', 'Next Run', 'Actions'].map(h => (
                        <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scheduled.map(j => (
                      <TableRow key={j.job_id} className="hover:bg-hover transition-colors">
                        <TableCell className="px-4 py-3 font-mono text-lit">{j.domain || '—'}</TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs">{j.job_type || '—'}</TableCell>
                        <TableCell className="px-4 py-3 text-dim">{fmtDate(j.next_run_time)}</TableCell>
                        <TableCell className="px-4 py-3">
                          <ConfirmButton label="Cancel" confirmLabel="Cancel job?" onConfirm={() => handleCancelJob(j.job_id)} />
                        </TableCell>
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
