import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Pagination } from '../components/Pagination.jsx';
import { Card } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import { apiGet } from '../api/client.js';
import { useQuery } from '@tanstack/react-query';

const KINDS    = ['subdomain', 'ip', 'port', 'url'];
const STATUSES = ['active', 'gone'];
const SEV      = ['critical', 'high', 'medium', 'low', 'info'];

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

// Compact per-severity finding counts — only render the non-zero buckets.
export function SeverityChips({ counts }) {
  const shown = SEV.filter(s => (counts?.[s] ?? 0) > 0);
  if (shown.length === 0) return <span className="text-dim text-xs">—</span>;
  return (
    <span className="inline-flex gap-1">
      {shown.map(s => <Badge key={s} value={s} label={`${counts[s]} ${s}`} />)}
    </span>
  );
}

export default function AssetsPage() {
  const navigate = useNavigate();
  const [kind,   setKind]   = useState('');
  const [status, setStatus] = useState('');
  const [domain, setDomain] = useState('');
  const [q,      setQ]      = useState('');
  const [page,   setPage]   = useState(1);

  const { data: domainsData } = useQuery({
    queryKey: ['/domains/'],
    queryFn: () => apiGet('/domains/'),
  });
  const { data, isLoading: loading, error } = useQuery({
    queryKey: ['/assets/', kind, status, domain, q, page],
    queryFn: () => apiGet(`/assets/?kind=${kind}&status=${status}&domain=${domain}&q=${encodeURIComponent(q)}&page=${page}`),
  });

  const assets  = data?.assets ?? [];
  const domains = domainsData || [];

  return (
    <Layout>
      <div className="space-y-5">
        <div>
          <h1 className="text-lit text-xl font-bold">Assets</h1>
          <p className="text-dim text-sm mt-0.5">Everything discovered across all scans — your attack surface over time</p>
        </div>

        <div className="flex gap-3 flex-wrap">
          <select value={kind} onChange={e => { setKind(e.target.value); setPage(1); }} className="field w-36">
            <option value="">All kinds</option>
            {KINDS.map(k => <option key={k} value={k}>{k}</option>)}
          </select>
          <select value={status} onChange={e => { setStatus(e.target.value); setPage(1); }} className="field w-32">
            <option value="">Any status</option>
            {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={domain} onChange={e => { setDomain(e.target.value); setPage(1); }} className="field w-52">
            <option value="">All domains</option>
            {domains.map(d => <option key={d.id} value={d.name}>{d.name}</option>)}
          </select>
          <input value={q} onChange={e => { setQ(e.target.value); setPage(1); }}
            placeholder="Search key…" className="field w-52" />
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
                      {['Kind', 'Asset', 'Domain', 'Status', 'Open findings', 'First seen', 'Last seen'].map(h => (
                        <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {assets.length === 0 ? (
                      <TableRow><TableCell colSpan={7} className="px-4 py-10 text-center text-dim">No assets.</TableCell></TableRow>
                    ) : assets.map(a => (
                      <TableRow key={a.id} onClick={() => navigate(`/assets/${a.id}`)}
                        className="hover:bg-hover transition-colors cursor-pointer">
                        <TableCell className="px-4 py-3"><Badge value={a.kind} /></TableCell>
                        <TableCell className="px-4 py-3 font-mono text-body text-xs max-w-xs truncate">{a.key}</TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs">{a.domain}</TableCell>
                        <TableCell className="px-4 py-3"><Badge value={a.status} /></TableCell>
                        <TableCell className="px-4 py-3"><SeverityChips counts={a.findings} /></TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs">{fmtDate(a.first_seen)}</TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs">{fmtDate(a.last_seen)}</TableCell>
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
