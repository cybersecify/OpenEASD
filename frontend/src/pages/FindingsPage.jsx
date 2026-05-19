import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Pagination } from '../components/Pagination.jsx';
import { Card, CardContent } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import { toast } from '../components/Notification.jsx';
import { apiPost } from '../api/client.js';
import { useFetch } from '../hooks/useFetch.js';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES   = ['open', 'acknowledged', 'in_progress', 'resolved', 'false_positive'];

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function StatusEditor({ findingId, current, onUpdated }) {
  const [editing, setEditing] = useState(false);
  const [saving,  setSaving]  = useState(false);

  async function handleChange(e) {
    const val = e.target.value;
    setSaving(true);
    try {
      await apiPost(`/scans/findings/${findingId}/status/`, { status: val });
      onUpdated(findingId, val);
    } finally { setSaving(false); setEditing(false); }
  }

  if (editing) {
    return (
      <select autoFocus defaultValue={current} onChange={handleChange}
        disabled={saving} className="field text-xs py-0.5 px-1 w-36">
        {STATUSES.map(s => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
      </select>
    );
  }
  return (
    <button onClick={() => setEditing(true)} className="text-left">
      <Badge value={current} />
    </button>
  );
}

export default function FindingsPage() {
  const params = new URLSearchParams(window.location.search);
  const [severity, setSeverity] = useState(params.get('severity') || '');
  const [status,   setStatus]   = useState('open');
  const [domain,   setDomain]   = useState(params.get('domain') || '');
  const [page,     setPage]     = useState(1);

  const { data: domainsData } = useFetch('/domains/');
  const { data, loading, error, pagination, refetch } = useFetch(
    `/scans/findings/?severity=${severity}&status=${status}&domain=${domain}&page=${page}`,
    [severity, status, domain, page],
  );

  const findings = data?.findings ?? [];
  const domains  = domainsData || [];

  return (
    <Layout>
      <div className="space-y-5">
        <div>
          <h1 className="text-lit text-xl font-bold">Findings</h1>
          <p className="text-dim text-sm mt-0.5">All findings across all scans</p>
        </div>

        <div className="flex gap-3 flex-wrap">
          <select value={severity} onChange={e => { setSeverity(e.target.value); setPage(1); }} className="field w-36">
            <option value="">All severities</option>
            {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={status} onChange={e => { setStatus(e.target.value); setPage(1); }} className="field w-40">
            <option value="">All statuses</option>
            {STATUSES.map(s => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
          </select>
          <select value={domain} onChange={e => { setDomain(e.target.value); setPage(1); }} className="field w-52">
            <option value="">All domains</option>
            {domains.map(d => <option key={d.id} value={d.name}>{d.name}</option>)}
          </select>
        </div>

        <Card className="overflow-hidden">
          {loading ? <div className="flex justify-center p-8"><Spinner /></div>
          : error   ? <div className="p-6 text-red-400 text-sm">Error: {error}</div>
          : (
            <>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      {['Severity', 'Title', 'Target', 'Source', 'Status', 'Found'].map(h => (
                        <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {findings.length === 0 ? (
                      <TableRow><TableCell colSpan={6} className="px-4 py-10 text-center text-dim">No findings.</TableCell></TableRow>
                    ) : findings.map(f => (
                      <TableRow key={f.id} className="hover:bg-hover transition-colors">
                        <TableCell className="px-4 py-3"><Badge value={f.severity} /></TableCell>
                        <TableCell className="px-4 py-3 text-body font-medium max-w-xs truncate">{f.title}</TableCell>
                        <TableCell className="px-4 py-3 font-mono text-dim text-xs">{f.target}</TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs">{f.source}</TableCell>
                        <TableCell className="px-4 py-3">
                          <StatusEditor findingId={f.id} current={f.status || 'open'}
                            onUpdated={() => { toast.success('Status updated.'); refetch(); }} />
                        </TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs">{fmtDate(f.discovered_at)}</TableCell>
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
        </Card>
      </div>
    </Layout>
  );
}
