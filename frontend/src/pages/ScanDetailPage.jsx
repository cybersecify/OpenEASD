import React, { useState, useEffect, useRef } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { ConfirmButton } from '../components/ConfirmButton.jsx';
import { toast } from '../components/Notification.jsx';
import { Pagination } from '../components/Pagination.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import {
  AlertDialog, AlertDialogCancel, AlertDialogContent,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../components/ui/alert-dialog.jsx';
import { useNavigate, useParams } from 'react-router-dom';
import { apiPost, apiGet } from '../api/client.js';
import { auth } from '../auth.js';
import { useFetch } from '../hooks/useFetch.js';
import { usePolling } from '../hooks/usePolling.js';

// Download report via authenticated fetch + Blob. The JWT travels in the
// Authorization header — never in the URL — so it doesn't leak into browser
// history, Referer, or server access logs.
async function downloadReport(uuid, kind, minSev) {
  const token = auth.getToken();
  const url = `/reports/${uuid}/${kind}/?min_severity=${encodeURIComponent(minSev)}`;
  try {
    const res = await fetch(url, {
      headers: { 'Authorization': `Bearer ${token}` },
    });
    if (!res.ok) {
      throw new Error(`Server returned ${res.status}`);
    }
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
  } catch (e) {
    toast.error(`Failed to download ${kind.toUpperCase()}: ${e.message}`);
  }
}

function SubScanDialog({ uuid, domain, onClose, onStarted }) {
  const [tools, setTools] = useState([]);
  const [selected, setSelected] = useState(new Set());
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    apiGet('/workflows/tools/').then(data => {
      const scanTools = data.filter(t => !['subfinder','amass','dnsx','naabu','service_detection'].includes(t.key));
      setTools(scanTools);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  function toggle(key) {
    setSelected(s => { const n = new Set(s); n.has(key) ? n.delete(key) : n.add(key); return n; });
  }

  async function handleRun() {
    if (!selected.size) { toast.error('Select at least one tool'); return; }
    setRunning(true);
    try {
      const res = await apiPost(`/scans/${uuid}/subscan/`, { tools: [...selected] });
      toast.success('Subscan started');
      onStarted(res.uuid);
      onClose();
    } catch (e) { toast.error(e.message || 'Failed to start subscan'); }
    finally { setRunning(false); }
  }

  return (
    <AlertDialog open onOpenChange={open => !open && onClose()}>
      <AlertDialogContent className="bg-card border border-rim max-w-sm">
        <AlertDialogHeader>
          <AlertDialogTitle className="text-lit">Re-run Tools on {domain}</AlertDialogTitle>
        </AlertDialogHeader>
        <div className="py-2 space-y-3">
          <p className="text-amber-400 text-xs border border-amber-800 bg-amber-900/20 rounded px-3 py-2">
            Assets (subdomains, IPs, ports, URLs) are copied from this scan. Run a full scan to refresh discovery.
          </p>
          {loading ? <Spinner size={20} /> : (
            <div className="space-y-1.5 max-h-64 overflow-y-auto">
              {tools.map(t => (
                <label key={t.key} className="flex items-center gap-2.5 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={selected.has(t.key)}
                    onChange={() => toggle(t.key)}
                    className="accent-brand"
                  />
                  <span className="text-sm text-body group-hover:text-lit">{t.label}</span>
                  {t.produces_findings && <span className="text-xs text-dim">(findings)</span>}
                </label>
              ))}
            </div>
          )}
        </div>
        <AlertDialogFooter className="flex gap-2">
          <AlertDialogCancel asChild>
            <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
          </AlertDialogCancel>
          <Button size="sm" onClick={handleRun} disabled={running || !selected.size}>
            {running ? 'Starting…' : `Run ${selected.size || ''} tool${selected.size !== 1 ? 's' : ''}`}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

const TABS = ['subdomains', 'ips', 'ports', 'urls', 'findings'];
const TERMINAL = new Set(['completed', 'partial', 'failed', 'cancelled']);
const PAGE_SIZE = 50;

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function fmtSize(bytes) {
  if (bytes == null) return '—';
  if (bytes === 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1_048_576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1_048_576).toFixed(1)} MB`;
}

function statusColor(code) {
  if (!code) return 'text-dim';
  if (code < 300) return 'text-green-400';
  if (code < 400) return 'text-yellow-400';
  if (code < 500) return 'text-orange-400';
  return 'text-red-400';
}

const SCHEME_CLS = {
  https: 'bg-blue-900/40 text-blue-400 border border-blue-800',
  http:  'bg-yellow-900/40 text-yellow-400 border border-yellow-800',
};

function StatCard({ label, value, danger }) {
  return (
    <div className={`border rounded-lg px-4 py-3 text-center ${danger ? 'border-red-800 bg-red-900/10' : 'border-rim bg-card'}`}>
      <div className={`text-xl font-bold ${danger ? 'text-red-400' : 'text-lit'}`}>{value ?? 0}</div>
      <div className="text-xs text-dim mt-0.5">{label}</div>
    </div>
  );
}

export default function ScanDetailPage() {
  const navigate = useNavigate();
  const { uuid } = useParams();
  const [tab,  setTab]  = useState('subdomains');
  const [page, setPage] = useState(1);
  const [busy, setBusy] = useState(false);
  const [showSubScan, setShowSubScan] = useState(false);
  const [schemeFilter, setSchemeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [minSev, setMinSev] = useState('info');

  const { data, loading, error, refetch } = useFetch(uuid ? `/scans/${uuid}/` : null, [uuid]);

  // Stop polling once scan reaches a terminal state
  const currentStatus = data?.session?.status;
  const pollPath = uuid && currentStatus && !TERMINAL.has(currentStatus)
    ? `/scans/${uuid}/status/` : null;
  const { data: statusData } = usePolling(pollPath, 3000);

  // When polling detects the scan reaching a terminal state, reload full data
  // so tabs (subdomains, IPs, ports, URLs, findings) show the completed results.
  const prevPollStatusRef = useRef(null);
  useEffect(() => {
    const pollStatus = statusData?.session?.status;
    if (
      pollStatus &&
      TERMINAL.has(pollStatus) &&
      prevPollStatusRef.current &&
      !TERMINAL.has(prevPollStatusRef.current)
    ) {
      refetch();
    }
    prevPollStatusRef.current = pollStatus;
  }, [statusData, refetch]);

  async function handleStop() {
    setBusy(true);
    try { await apiPost(`/scans/${uuid}/stop/`); toast.success('Scan stopped.'); refetch(); }
    catch (e) { toast.error(e.message || 'Stop failed.'); }
    finally { setBusy(false); }
  }

  async function handleDelete() {
    setBusy(true);
    try { await apiPost(`/scans/${uuid}/delete/`); navigate('/scans'); }
    catch (e) { toast.error(e.message || 'Delete failed.'); setBusy(false); }
  }

  if (loading) return <Layout><div className="flex justify-center items-center h-64"><Spinner size={40} /></div></Layout>;
  if (error)   return <Layout><div className="text-red-400 p-4">Error: {error}</div></Layout>;
  if (!data)   return <Layout><div /></Layout>;

  const session     = data.session || {};
  const liveStatus  = statusData?.session?.status || session.status;
  const isRunning   = liveStatus === 'running';
  const assetCounts = statusData?.asset_counts || data.asset_counts || {};
  const vulnCounts  = statusData?.vuln_counts  || data.vuln_counts  || {};

  const subdomains = data.subdomains || [];
  const ips        = data.ips        || [];
  const ports      = data.ports      || [];
  const urls       = data.urls       || [];
  const findings   = [
    ...(data.nmap_findings    || []),
    ...(data.domain_findings  || []),
    ...(data.other_findings   || []),
  ].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
  });

  const tabData = { subdomains, ips, ports, urls, findings };

  const filteredUrls = urls.filter(u => {
    if (schemeFilter && u.scheme !== schemeFilter) return false;
    if (statusFilter && !String(u.status_code ?? '').startsWith(statusFilter)) return false;
    return true;
  });

  const items      = tab === 'urls' ? filteredUrls : (tabData[tab] || []);
  const paged      = items.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const totalPages = Math.ceil(items.length / PAGE_SIZE);

  return (
    <Layout>
      <div className="space-y-5">

        {/* Header */}
        <div className="flex items-start justify-between flex-wrap gap-3">
          <div>
            <button onClick={() => navigate('/scans')} className="text-dim text-xs hover:text-body mb-1 block">← Scans</button>
            <h1 className="text-lit text-xl font-bold font-mono">{session.domain_name}</h1>
            <div className="flex items-center gap-2 mt-1 flex-wrap">
              <Badge value={liveStatus} />
              {isRunning && <Spinner size={14} />}
            </div>
            <p className="text-dim text-xs mt-1">
              Started: {fmtDate(session.start_time)}{session.end_time && <> · Finished: {fmtDate(session.end_time)}</>}
            </p>
          </div>
          <span className="inline-flex gap-1.5 items-center flex-wrap">
            {isRunning && <ConfirmButton label="Stop" confirmLabel="Stop scan?" onConfirm={handleStop} disabled={busy} />}
            {liveStatus === 'completed' && (
              <Button variant="outline" size="sm" onClick={() => setShowSubScan(true)}>Re-scan Tools</Button>
            )}
            {(liveStatus === 'completed' || liveStatus === 'partial') && (<>
              <select
                value={minSev}
                onChange={e => setMinSev(e.target.value)}
                className="h-8 rounded-md border border-rim bg-canvas px-2 text-xs text-lit focus:outline-none focus:ring-1 focus:ring-brand"
              >
                <option value="info">All severities</option>
                <option value="low">Low+</option>
                <option value="medium">Medium+</option>
                <option value="high">High+</option>
                <option value="critical">Critical only</option>
              </select>
              <Button variant="outline" size="sm" onClick={() => downloadReport(uuid, 'csv', minSev)}>CSV</Button>
              <Button variant="outline" size="sm" onClick={() => downloadReport(uuid, 'pdf', minSev)}>PDF</Button>
            </>)}
            <ConfirmButton label="Delete" onConfirm={handleDelete} disabled={busy} />
          </span>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
          <StatCard label="Subdomains" value={assetCounts.subdomains_total} />
          <StatCard label="IPs"        value={assetCounts.ips} />
          <StatCard label="Ports"      value={assetCounts.ports} />
          <StatCard label="URLs"       value={assetCounts.urls} />
          <StatCard label="Critical"   value={vulnCounts.critical} danger />
          <StatCard label="Findings"   value={session.total_findings} />
        </div>

        {/* Tabs */}
        <div>
          <div className="flex gap-0.5 border-b border-rim mb-4">
            {TABS.map(t => (
              <button key={t} onClick={() => { setTab(t); setPage(1); setSchemeFilter(''); setStatusFilter(''); }}
                className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors capitalize
                  ${t === tab ? 'border-brand text-brand' : 'border-transparent text-dim hover:text-body'}`}>
                {t} ({t === 'urls' ? filteredUrls.length : (tabData[t] || []).length})
              </button>
            ))}
          </div>

          <Card className="overflow-hidden">
            {tab === 'urls' && (
              <div className="flex gap-3 px-4 pt-4 pb-2 flex-wrap">
                <select
                  value={schemeFilter}
                  onChange={e => { setSchemeFilter(e.target.value); setPage(1); }}
                  className="field w-32"
                >
                  <option value="">All schemes</option>
                  <option value="https">https</option>
                  <option value="http">http</option>
                </select>
                <input
                  type="text"
                  inputMode="numeric"
                  value={statusFilter}
                  onChange={e => { setStatusFilter(e.target.value.trim()); setPage(1); }}
                  placeholder="Status code…"
                  className="field w-36"
                />
              </div>
            )}
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <Table>
                  {tab === 'subdomains' && <>
                    <TableHeader><TableRow>{['Subdomain', 'Active', 'Discovered'].map(h => <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>)}</TableRow></TableHeader>
                    <TableBody>
                      {paged.length === 0
                        ? <TableRow><TableCell colSpan={3} className="px-4 py-8 text-center text-dim">None found.</TableCell></TableRow>
                        : paged.map(s => (
                          <TableRow key={s.id} className="hover:bg-hover">
                            <TableCell className="px-4 py-3 font-mono text-lit">{s.subdomain}</TableCell>
                            <TableCell className="px-4 py-3"><Badge value={s.is_active ? 'active' : 'inactive'} /></TableCell>
                            <TableCell className="px-4 py-3 text-dim text-xs">{fmtDate(s.discovered_at)}</TableCell>
                          </TableRow>
                        ))}
                    </TableBody>
                  </>}
                  {tab === 'ips' && <>
                    <TableHeader><TableRow>{['IP', 'Version', 'Source'].map(h => <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>)}</TableRow></TableHeader>
                    <TableBody>
                      {paged.length === 0
                        ? <TableRow><TableCell colSpan={3} className="px-4 py-8 text-center text-dim">None found.</TableCell></TableRow>
                        : paged.map(ip => (
                          <TableRow key={ip.id} className="hover:bg-hover">
                            <TableCell className="px-4 py-3 font-mono text-lit">{ip.address}</TableCell>
                            <TableCell className="px-4 py-3 text-dim text-xs">v{ip.version}</TableCell>
                            <TableCell className="px-4 py-3 text-dim text-xs">{ip.source || '—'}</TableCell>
                          </TableRow>
                        ))}
                    </TableBody>
                  </>}
                  {tab === 'ports' && <>
                    <TableHeader><TableRow>{['Host', 'Port', 'Service', 'Version', 'Web?'].map(h => <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>)}</TableRow></TableHeader>
                    <TableBody>
                      {paged.length === 0
                        ? <TableRow><TableCell colSpan={5} className="px-4 py-8 text-center text-dim">None found.</TableCell></TableRow>
                        : paged.map(p => (
                          <TableRow key={p.id} className="hover:bg-hover">
                            <TableCell className="px-4 py-3 font-mono text-dim text-xs">{p.address}</TableCell>
                            <TableCell className="px-4 py-3 font-mono text-lit font-semibold">{p.port}/{p.protocol}</TableCell>
                            <TableCell className="px-4 py-3 text-dim">{p.service || '—'}</TableCell>
                            <TableCell className="px-4 py-3 text-dim text-xs">{p.version || '—'}</TableCell>
                            <TableCell className="px-4 py-3">{p.is_web ? <Badge value="web" /> : <span className="text-dim">—</span>}</TableCell>
                          </TableRow>
                        ))}
                    </TableBody>
                  </>}
                  {tab === 'urls' && <>
                    <TableHeader>
                      <TableRow>
                        {['Scheme', 'URL', 'Status', 'Title', 'Server', 'Size'].map(h =>
                          <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                        )}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {paged.length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={6} className="px-4 py-8 text-center text-dim">
                            {(schemeFilter || statusFilter) ? 'No URLs match the current filters.' : 'No URLs discovered yet.'}
                          </TableCell>
                        </TableRow>
                      ) : paged.map(u => (
                        <TableRow key={u.id} className="hover:bg-hover">
                          <TableCell className="px-4 py-3">
                            <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold uppercase ${SCHEME_CLS[u.scheme] ?? 'bg-gray-800/60 text-gray-400 border border-gray-700'}`}>
                              {u.scheme || '—'}
                            </span>
                          </TableCell>
                          <TableCell className="px-4 py-3 font-mono text-brand text-xs max-w-xs truncate">
                            <a href={u.url} target="_blank" rel="noopener noreferrer" className="hover:underline">{u.url}</a>
                          </TableCell>
                          <TableCell className={`px-4 py-3 font-mono font-semibold ${statusColor(u.status_code)}`}>
                            {u.status_code || '—'}
                          </TableCell>
                          <TableCell className="px-4 py-3 text-body text-xs max-w-xs truncate">{u.title || '—'}</TableCell>
                          <TableCell className="px-4 py-3 text-dim text-xs">{u.web_server || '—'}</TableCell>
                          <TableCell className="px-4 py-3 text-dim text-xs">{fmtSize(u.content_length)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </>}
                  {tab === 'findings' && <>
                    <TableHeader><TableRow>{['Sev', 'Title', 'Target', 'Source'].map(h => <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>)}</TableRow></TableHeader>
                    <TableBody>
                      {paged.length === 0
                        ? <TableRow><TableCell colSpan={4} className="px-4 py-8 text-center text-dim">None found.</TableCell></TableRow>
                        : paged.map(f => (
                          <TableRow key={f.id} className="hover:bg-hover">
                            <TableCell className="px-4 py-3"><Badge value={f.severity} /></TableCell>
                            <TableCell className="px-4 py-3 text-body font-medium max-w-xs truncate">{f.title}</TableCell>
                            <TableCell className="px-4 py-3 font-mono text-dim text-xs">{f.target}</TableCell>
                            <TableCell className="px-4 py-3 text-dim text-xs">{f.source}</TableCell>
                          </TableRow>
                        ))}
                    </TableBody>
                  </>}
                </Table>
              </div>
            </CardContent>
            {totalPages > 1 && (
              <div className="px-4 py-3 border-t border-border">
                <Pagination page={page} totalPages={totalPages} onPage={setPage} />
              </div>
            )}
          </Card>
        </div>
      </div>

      {showSubScan && (
        <SubScanDialog
          uuid={uuid}
          domain={session.domain_name}
          onClose={() => setShowSubScan(false)}
          onStarted={newUuid => navigate(`/scans/${newUuid}`)}
        />
      )}
    </Layout>
  );
}
