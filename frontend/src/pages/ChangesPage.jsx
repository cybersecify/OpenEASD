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

function fmtWhen(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export default function ChangesPage() {
  const navigate = useNavigate();
  const [changeType, setChangeType] = useState('');
  const [domain,     setDomain]     = useState('');
  const [page,       setPage]       = useState(1);

  const { data, isLoading: loading, error } = useQuery({
    queryKey: ['/changes/', changeType, domain, page],
    queryFn: () => apiGet(`/changes/?change_type=${changeType}`
      + `&domain=${encodeURIComponent(domain)}&page=${page}`),
  });

  const deltas     = data?.deltas ?? [];
  const totalPages = data ? data.total_pages : 1;
  const reset = (fn) => (v) => { fn(v); setPage(1); };

  return (
    <Layout>
      <div className="space-y-5">
        <div>
          <h1 className="text-lit text-xl font-bold">Changes</h1>
          <p className="text-dim text-sm mt-0.5">
            What appeared and disappeared between scans — newest first. New findings are worth a look; removed ones may be fixed or a coverage gap.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <select value={changeType} onChange={e => reset(setChangeType)(e.target.value)} className="field w-40">
            <option value="">All changes</option>
            <option value="new">New</option>
            <option value="removed">Removed</option>
          </select>
          <input value={domain} onChange={e => reset(setDomain)(e.target.value)}
            placeholder="Filter by domain…" className="field flex-1 min-w-[180px]" />
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
                      {['Change', 'Finding', 'Source', 'Domain', 'When', ''].map((h, idx) => (
                        <TableHead key={idx} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {deltas.length === 0 ? (
                      <TableRow><TableCell colSpan={6} className="px-4 py-10 text-center text-dim">
                        No changes recorded yet — deltas appear after a domain's second scan.
                      </TableCell></TableRow>
                    ) : deltas.map(d => (
                      <TableRow key={d.id} className="hover:bg-hover transition-colors">
                        <TableCell className="px-4 py-3">
                          <Badge value={d.change_type === 'new' ? 'open' : 'resolved'}
                            label={d.change_type === 'new' ? 'new' : 'removed'} />
                        </TableCell>
                        <TableCell className="px-4 py-3 text-body font-medium max-w-md truncate" title={d.title}>{d.title || '—'}</TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs">{d.source}{d.check_type ? ` / ${d.check_type}` : ''}</TableCell>
                        <TableCell className="px-4 py-3 text-dim font-mono text-xs">{d.domain}</TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs whitespace-nowrap">{fmtWhen(d.created_at)}</TableCell>
                        <TableCell className="px-4 py-3">
                          <button onClick={() => navigate(`/scans/${d.scan_uuid}`)} className="text-brand hover:underline text-xs">scan →</button>
                        </TableCell>
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
