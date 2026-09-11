import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Pagination } from '../components/Pagination.jsx';
import { Card } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import { toast } from '../components/Notification.jsx';
import { apiGet, apiPost } from '../api/client.js';
import { useQuery } from '@tanstack/react-query';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES   = ['open', 'acknowledged', 'in_progress', 'resolved', 'false_positive'];

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

// Inline triage editor — persists to the Issue (survives future scans), unlike
// the old per-scan finding status.
function StatusEditor({ issueId, current, onUpdated }) {
  const [saving, setSaving] = useState(false);
  async function handleChange(e) {
    const status = e.target.value;
    setSaving(true);
    try {
      await apiPost(`/issues/${issueId}/status/`, { status });
      toast.success(`Marked ${status.replace(/_/g, ' ')} (persists across scans)`);
      onUpdated();
    } catch (err) {
      toast.error(err.message || 'Failed to update status.');
    } finally {
      setSaving(false);
    }
  }
  return (
    <select value={current} onChange={handleChange} disabled={saving}
      className="field text-xs py-0.5 px-1 w-36">
      {STATUSES.map(s => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
    </select>
  );
}

export default function FindingsPage() {
  const navigate = useNavigate();
  const [status,   setStatus]   = useState('open');   // default to the actionable set
  const [severity, setSeverity] = useState('');
  const [domain,   setDomain]   = useState('');
  const [q,        setQ]        = useState('');
  const [page,     setPage]     = useState(1);

  const { data: summary } = useQuery({
    queryKey: ['/issues/summary/', domain],
    queryFn: () => apiGet(`/issues/summary/?domain=${encodeURIComponent(domain)}`),
  });
  const { data, isLoading: loading, error, refetch } = useQuery({
    queryKey: ['/issues/', status, severity, domain, q, page],
    queryFn: () => apiGet(`/issues/?status=${status}&severity=${severity}`
      + `&domain=${encodeURIComponent(domain)}&q=${encodeURIComponent(q)}&page=${page}`),
  });

  const issues     = data?.issues ?? [];
  const totalPages = data ? data.total_pages : 1;
  const openSev    = summary?.open_by_severity ?? {};

  const reset = (fn) => (v) => { fn(v); setPage(1); };

  return (
    <Layout>
      <div className="space-y-5">
        <div>
          <h1 className="text-lit text-xl font-bold">Findings</h1>
          <p className="text-dim text-sm mt-0.5">
            Persistent issue register — one row per distinct finding across scans; triage sticks.
          </p>
        </div>

        {/* Actionable-severity summary. NOTE: an empty list means "nothing open
            in the register", NOT necessarily "surface is clean" — check Scans for
            coverage / partial runs. */}
        <div className="flex flex-wrap gap-2">
          {SEVERITIES.map(s => (
            <Badge key={s} value={s} label={`${openSev[s] ?? 0} ${s}`} />
          ))}
          <span className="text-dim text-xs self-center ml-1">open/acknowledged/in-progress</span>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-2">
          <select value={status} onChange={e => reset(setStatus)(e.target.value)} className="field w-40">
            <option value="">All statuses</option>
            {STATUSES.map(s => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
          </select>
          <select value={severity} onChange={e => reset(setSeverity)(e.target.value)} className="field w-36">
            <option value="">All severities</option>
            {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <input value={domain} onChange={e => reset(setDomain)(e.target.value)}
            placeholder="Filter by domain…" className="field w-48" />
          <input value={q} onChange={e => reset(setQ)(e.target.value)}
            placeholder="Search title…" className="field flex-1 min-w-[180px]" />
        </div>

        <Card className="overflow-hidden">
          {loading ? (
            <div className="flex justify-center p-8"><Spinner /></div>
          ) : error ? (
            <div className="p-6 text-red-400 text-sm">Error: {error?.message ?? String(error)}</div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      {['Severity', 'Finding', 'Source', 'Target', 'Domain', 'Last seen', 'Status'].map(h => (
                        <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {issues.length === 0 ? (
                      <TableRow><TableCell colSpan={7} className="px-4 py-10 text-center text-dim">
                        No issues match. (Empty ≠ clean — check Scans for coverage.)
                      </TableCell></TableRow>
                    ) : issues.map(i => (
                      <TableRow key={i.id} className="hover:bg-hover transition-colors">
                        <TableCell className="px-4 py-3"><Badge value={i.severity} /></TableCell>
                        <TableCell className="px-4 py-3 text-body font-medium max-w-md truncate" title={i.title}>{i.title}</TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs">{i.source}{i.check_type ? ` / ${i.check_type}` : ''}</TableCell>
                        <TableCell className="px-4 py-3 font-mono text-xs">
                          {i.asset_id ? (
                            <button onClick={() => navigate(`/assets/${i.asset_id}`)} className="text-brand hover:underline">{i.target || '—'}</button>
                          ) : (i.target || '—')}
                        </TableCell>
                        <TableCell className="px-4 py-3 text-dim font-mono text-xs">{i.domain}</TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs whitespace-nowrap">{fmtDate(i.last_seen)}</TableCell>
                        <TableCell className="px-4 py-3"><StatusEditor issueId={i.id} current={i.status} onUpdated={refetch} /></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              {totalPages > 1 && (
                <div className="px-4 py-3 border-t border-border">
                  <Pagination page={page} totalPages={totalPages} onPage={setPage} />
                </div>
              )}
            </>
          )}
        </Card>
      </div>
    </Layout>
  );
}
