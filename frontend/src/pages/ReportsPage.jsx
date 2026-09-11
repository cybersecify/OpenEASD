import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Pagination } from '../components/Pagination.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import { toast } from '../components/Notification.jsx';
import { apiGet } from '../api/client.js';
import { auth } from '../auth.js';
import { useQuery } from '@tanstack/react-query';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

// Download a report via authenticated fetch + Blob — the JWT travels in the
// Authorization header, never in the URL (same approach as ScanDetailPage).
async function downloadReport(uuid, kind, minSev) {
  const token = auth.getToken();
  const url = `/reports/${uuid}/${kind}/?min_severity=${encodeURIComponent(minSev)}`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) throw new Error(`Server returned ${res.status}`);
  const blob = await res.blob();
  const dispo = res.headers.get('Content-Disposition') || '';
  const match = dispo.match(/filename="?([^";]+)"?/);
  const filename = match ? match[1] : `report.${kind}`;
  const blobUrl = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(blobUrl);
}

export default function ReportsPage() {
  const [domain, setDomain] = useState('');
  const [minSev, setMinSev] = useState('info');
  const [page, setPage] = useState(1);
  const [busy, setBusy] = useState('');   // "<uuid>:<kind>" currently downloading

  const { data: domainsData } = useQuery({
    queryKey: ['/domains/'],
    queryFn: () => apiGet('/domains/'),
  });
  // Reports are of a finished scan → list completed + partial only.
  const { data, isLoading: loading, error } = useQuery({
    queryKey: ['/scans/', 'reports', domain, page],
    queryFn: () => apiGet(`/scans/?domain=${domain}&status=completed&page=${page}`),
  });

  const scans = data?.results ?? [];
  const domains = domainsData || [];

  async function handleDownload(uuid, kind) {
    const key = `${uuid}:${kind}`;
    setBusy(key);
    try {
      await downloadReport(uuid, kind, minSev);
    } catch (err) {
      toast.error(err.message || `Failed to generate ${kind.toUpperCase()} report.`);
    } finally {
      setBusy('');
    }
  }

  return (
    <Layout>
      <div className="space-y-5">
        <div>
          <h1 className="text-lit text-xl font-bold">Reports</h1>
          <p className="text-dim text-sm mt-0.5">Export a CSV or PDF report for any completed scan</p>
        </div>

        <div className="flex gap-3 flex-wrap items-center">
          <select value={domain} onChange={e => { setDomain(e.target.value); setPage(1); }} className="field w-52">
            <option value="">All domains</option>
            {domains.map(d => <option key={d.id} value={d.name}>{d.name}</option>)}
          </select>
          <label className="text-dim text-sm flex items-center gap-2">
            Min severity
            <select value={minSev} onChange={e => setMinSev(e.target.value)} className="field w-32">
              {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <span className="text-dim text-xs">applies to the exported report contents</span>
        </div>

        <Card className="overflow-hidden">
          {loading ? <div className="flex justify-center p-8"><Spinner /></div>
          : error   ? <div className="p-6 text-red-400 text-sm">Error: {error?.message ?? String(error)}</div>
          : (
            <>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      {['Domain', 'Status', 'Findings', 'Completed', 'Report'].map(h => (
                        <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scans.length === 0 ? (
                      <TableRow><TableCell colSpan={5} className="px-4 py-10 text-center text-dim">No completed scans to report on.</TableCell></TableRow>
                    ) : scans.map(s => (
                      <TableRow key={s.uuid} className="hover:bg-hover transition-colors">
                        <TableCell className="px-4 py-3 text-body font-medium">{s.domain_name}</TableCell>
                        <TableCell className="px-4 py-3"><Badge value={s.status} /></TableCell>
                        <TableCell className="px-4 py-3 text-dim text-sm">{s.total_findings}</TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs">{fmtDate(s.end_time)}</TableCell>
                        <TableCell className="px-4 py-3">
                          <div className="flex gap-2">
                            <Button variant="outline" size="sm" disabled={busy === `${s.uuid}:csv`}
                              onClick={() => handleDownload(s.uuid, 'csv')}>
                              {busy === `${s.uuid}:csv` ? '…' : 'CSV'}
                            </Button>
                            <Button variant="outline" size="sm" disabled={busy === `${s.uuid}:pdf`}
                              onClick={() => handleDownload(s.uuid, 'pdf')}>
                              {busy === `${s.uuid}:pdf` ? '…' : 'PDF'}
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              {data?.total_pages > 1 && (
                <div className="px-4 py-3 border-t border-border">
                  <Pagination page={page} totalPages={data.total_pages} onPage={setPage} />
                </div>
              )}
            </>
          )}
        </Card>
      </div>
    </Layout>
  );
}
