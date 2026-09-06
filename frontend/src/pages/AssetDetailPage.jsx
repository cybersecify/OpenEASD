import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import { apiGet } from '../api/client.js';
import { useQuery } from '@tanstack/react-query';

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

export default function AssetDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();

  const { data: a, isLoading: loading, error } = useQuery({
    queryKey: [`/assets/${id}/`],
    queryFn: () => apiGet(`/assets/${id}/`),
  });

  if (loading) return <Layout><div className="flex justify-center p-8"><Spinner /></div></Layout>;
  if (error) return <Layout><div className="p-6 text-red-400 text-sm">Error: {error?.message ?? String(error)}</div></Layout>;

  const findings = a?.findings ?? [];
  const timeline = a?.seen_in_scans ?? [];
  const extra = a?.extra ?? {};

  return (
    <Layout>
      <div className="space-y-5">
        <button onClick={() => navigate('/assets')} className="text-dim text-sm hover:text-body">← Assets</button>

        <div className="flex items-center gap-3 flex-wrap">
          <Badge value={a.kind} />
          <h1 className="text-lit text-xl font-bold font-mono break-all">{a.key}</h1>
          <Badge value={a.status} />
        </div>

        <Card>
          <CardContent className="grid grid-cols-2 gap-x-8 gap-y-2 p-5 text-sm md:grid-cols-4">
            <div><div className="text-dim text-xs uppercase">Domain</div><div className="text-body">{a.domain}</div></div>
            <div><div className="text-dim text-xs uppercase">First seen</div><div className="text-body">{fmtDate(a.first_seen)}</div></div>
            <div><div className="text-dim text-xs uppercase">Last seen</div><div className="text-body">{fmtDate(a.last_seen)}</div></div>
            <div><div className="text-dim text-xs uppercase">Last scan</div>
              <div className="text-body">
                {a.last_scan ? <button className="text-green-400 hover:underline font-mono text-xs" onClick={() => navigate(`/scans/${a.last_scan}`)}>{a.last_scan.slice(0, 8)}</button> : '—'}
              </div>
            </div>
            {Object.entries(extra).filter(([, v]) => v !== '' && v !== null && v !== undefined).map(([k, v]) => (
              <div key={k}><div className="text-dim text-xs uppercase">{k.replace(/_/g, ' ')}</div>
                <div className="text-body break-all">{Array.isArray(v) ? (v.join(', ') || '—') : String(v)}</div></div>
            ))}
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader className="px-5 pt-4 pb-0"><CardTitle className="text-base">Findings ({findings.length})</CardTitle></CardHeader>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  {['Severity', 'Title', 'Source', 'Status', 'Scan'].map(h => (
                    <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim">{h}</TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.length === 0 ? (
                  <TableRow><TableCell colSpan={5} className="px-4 py-8 text-center text-dim">No findings linked to this asset.</TableCell></TableRow>
                ) : findings.map(f => (
                  <TableRow key={f.id} className="hover:bg-hover transition-colors">
                    <TableCell className="px-4 py-3"><Badge value={f.severity} /></TableCell>
                    <TableCell className="px-4 py-3 text-body max-w-md truncate">{f.title}</TableCell>
                    <TableCell className="px-4 py-3 text-dim text-xs">{f.source}</TableCell>
                    <TableCell className="px-4 py-3"><Badge value={f.status || 'open'} /></TableCell>
                    <TableCell className="px-4 py-3">
                      {f.session_uuid ? <button className="text-green-400 hover:underline font-mono text-xs" onClick={() => navigate(`/scans/${f.session_uuid}`)}>{f.session_uuid.slice(0, 8)}</button> : '—'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader className="px-5 pt-4 pb-0"><CardTitle className="text-base">Seen in scans ({timeline.length})</CardTitle></CardHeader>
          <CardContent className="p-5 space-y-2">
            {timeline.length === 0 ? <div className="text-dim text-sm">No scan history.</div>
            : timeline.map(t => (
              <div key={t.uuid} className="flex items-center gap-3 text-sm">
                <button className="text-green-400 hover:underline font-mono text-xs" onClick={() => navigate(`/scans/${t.uuid}`)}>{t.uuid.slice(0, 8)}</button>
                <Badge value={t.status} />
                <span className="text-dim text-xs">{fmtDate(t.at)}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </Layout>
  );
}
