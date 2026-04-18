import React, { useState, useEffect, useRef } from 'react';
import { useFetch } from '../hooks/useFetch.js';
import { usePolling } from '../hooks/usePolling.js';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { ConfirmButton } from '../components/ConfirmButton.jsx';
import { Notification } from '../components/Notification.jsx';
import { apiPost } from '../api/client.js';
import { navigate } from '../App.jsx';

// ── constants ────────────────────────────────────────────────────────────────
const BG       = '#0d1117';
const CARD     = '#161b22';
const BORDER   = '#30363d';
const TEXT     = '#c9d1d9';
const MUTED    = '#8b949e';
const GREEN    = '#30c074';

const TERMINAL = new Set(['completed', 'failed', 'cancelled']);

// ── helpers ──────────────────────────────────────────────────────────────────
function fmtTime(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  } catch {
    return iso;
  }
}

function fmtDuration(start, end) {
  if (!start || !end) return null;
  const ms = new Date(end) - new Date(start);
  if (ms < 0) return null;
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  if (m === 0) return `${s}s`;
  const h = Math.floor(m / 60);
  if (h === 0) return `${m}m ${s % 60}s`;
  return `${h}h ${m % 60}m`;
}

// ── shared style helpers ─────────────────────────────────────────────────────
const card = (extra = {}) => ({
  background: CARD,
  border: `1px solid ${BORDER}`,
  borderRadius: '8px',
  padding: '1rem 1.25rem',
  ...extra,
});

const th = {
  padding: '0.5rem 0.75rem',
  textAlign: 'left',
  fontSize: '0.75rem',
  fontWeight: 600,
  color: MUTED,
  borderBottom: `1px solid ${BORDER}`,
  whiteSpace: 'nowrap',
};

const td = (extra = {}) => ({
  padding: '0.5rem 0.75rem',
  fontSize: '0.8rem',
  color: TEXT,
  borderBottom: `1px solid ${BORDER}22`,
  verticalAlign: 'middle',
  ...extra,
});

// ── severity colours for vuln cards ──────────────────────────────────────────
const SCARD = {
  critical: { border: '#dc2626', text: '#dc2626', bg: '#dc262611' },
  high:     { border: '#ea580c', text: '#ea580c', bg: '#ea580c11' },
  medium:   { border: '#ca8a04', text: '#ca8a04', bg: '#ca8a0411' },
  low:      { border: '#2563eb', text: '#2563eb', bg: '#2563eb11' },
};

// ── sub-components ───────────────────────────────────────────────────────────

function VulnCard({ severity, count }) {
  const c = SCARD[severity] || { border: BORDER, text: MUTED, bg: 'transparent' };
  return (
    <div style={{
      flex: '1 1 100px',
      background: c.bg,
      border: `1px solid ${c.border}`,
      borderRadius: '8px',
      padding: '1rem',
      textAlign: 'center',
    }}>
      <div style={{ fontSize: '1.75rem', fontWeight: 700, color: c.text }}>{count ?? 0}</div>
      <div style={{ fontSize: '0.75rem', color: c.text, textTransform: 'capitalize', marginTop: '2px' }}>{severity}</div>
    </div>
  );
}

function AssetCountBadge({ label, value, sub }) {
  return (
    <div style={card({ textAlign: 'center', flex: '1 1 100px' })}>
      <div style={{ fontSize: '1.5rem', fontWeight: 700, color: GREEN }}>{value ?? 0}</div>
      <div style={{ fontSize: '0.75rem', color: MUTED, marginTop: '2px' }}>{label}</div>
      {sub && <div style={{ fontSize: '0.7rem', color: MUTED }}>{sub}</div>}
    </div>
  );
}

function StepResultRow({ step }) {
  const duration = fmtDuration(step.started_at, step.finished_at);
  return (
    <tr>
      <td style={td()}>{step.tool}</td>
      <td style={td()}><Badge value={step.status} /></td>
      <td style={td({ color: MUTED })}>{step.findings_count ?? '—'}</td>
      <td style={td({ color: MUTED, fontSize: '0.75rem' })}>{fmtTime(step.started_at)}</td>
      <td style={td({ color: MUTED, fontSize: '0.75rem' })}>{fmtTime(step.finished_at)}</td>
      <td style={td({ color: MUTED })}>{duration || '—'}</td>
      <td style={td({ color: '#dc2626', maxWidth: '250px', wordBreak: 'break-word' })}>{step.error || ''}</td>
    </tr>
  );
}

function SectionTable({ columns, rows, renderRow, emptyMsg = 'No data.' }) {
  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
        <thead>
          <tr>{columns.map(c => <th key={c} style={th}>{c}</th>)}</tr>
        </thead>
        <tbody>
          {rows && rows.length > 0
            ? rows.map((row, i) => <React.Fragment key={i}>{renderRow(row, i)}</React.Fragment>)
            : <tr><td colSpan={columns.length} style={{ ...td(), color: MUTED, textAlign: 'center', padding: '1.5rem' }}>{emptyMsg}</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function SubdomainsTab({ subdomains }) {
  return (
    <SectionTable
      columns={['Subdomain', 'Domain', 'Active', 'Source', 'Discovered']}
      rows={subdomains}
      renderRow={r => (
        <tr>
          <td style={td({ fontFamily: 'monospace' })}>{r.subdomain}</td>
          <td style={td({ color: MUTED })}>{r.domain}</td>
          <td style={td()}>{r.is_active ? <span style={{ color: GREEN }}>yes</span> : <span style={{ color: MUTED }}>no</span>}</td>
          <td style={td({ color: MUTED })}>{r.source || '—'}</td>
          <td style={td({ color: MUTED, fontSize: '0.75rem' })}>{fmtTime(r.discovered_at)}</td>
        </tr>
      )}
      emptyMsg="No subdomains discovered."
    />
  );
}

function IPsTab({ ips }) {
  return (
    <SectionTable
      columns={['IP Address', 'Version', 'Source', 'Subdomain ID']}
      rows={ips}
      renderRow={r => (
        <tr>
          <td style={td({ fontFamily: 'monospace' })}>{r.address}</td>
          <td style={td({ color: MUTED })}>{r.version === 6 ? 'IPv6' : 'IPv4'}</td>
          <td style={td({ color: MUTED })}>{r.source || '—'}</td>
          <td style={td({ color: MUTED })}>{r.subdomain_id ?? '—'}</td>
        </tr>
      )}
      emptyMsg="No IPs discovered."
    />
  );
}

function PortsTab({ ports }) {
  return (
    <SectionTable
      columns={['Address', 'Port', 'Protocol', 'State', 'Service', 'Version', 'Web', 'Source']}
      rows={ports}
      renderRow={r => (
        <tr>
          <td style={td({ fontFamily: 'monospace' })}>{r.address}</td>
          <td style={td({ fontFamily: 'monospace' })}>{r.port}</td>
          <td style={td({ color: MUTED })}>{r.protocol}</td>
          <td style={td()}>
            <Badge value={r.state === 'open' ? 'completed' : 'cancelled'} label={r.state} />
          </td>
          <td style={td({ color: MUTED })}>{r.service || '—'}</td>
          <td style={td({ color: MUTED })}>{r.version || '—'}</td>
          <td style={td()}>
            {r.is_web ? <span style={{ color: GREEN }}>yes</span> : <span style={{ color: MUTED }}>no</span>}
          </td>
          <td style={td({ color: MUTED })}>{r.source || '—'}</td>
        </tr>
      )}
      emptyMsg="No ports discovered."
    />
  );
}

function URLsTab({ urls }) {
  return (
    <SectionTable
      columns={['URL', 'Scheme', 'Host', 'Status', 'Title', 'Server']}
      rows={urls}
      renderRow={r => (
        <tr>
          <td style={td()}>
            <a href={r.url} target="_blank" rel="noreferrer"
              style={{ color: GREEN, fontSize: '0.78rem', wordBreak: 'break-all' }}>
              {r.url}
            </a>
          </td>
          <td style={td({ color: MUTED })}>{r.scheme}</td>
          <td style={td({ fontFamily: 'monospace', fontSize: '0.75rem' })}>{r.host}</td>
          <td style={td()}>
            {r.status_code
              ? <span style={{ color: r.status_code < 400 ? GREEN : '#ea580c' }}>{r.status_code}</span>
              : '—'}
          </td>
          <td style={td({ color: MUTED, maxWidth: '220px', overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis' })}>{r.title || '—'}</td>
          <td style={td({ color: MUTED })}>{r.web_server || '—'}</td>
        </tr>
      )}
      emptyMsg="No URLs discovered."
    />
  );
}

function FindingRow({ f }) {
  return (
    <tr>
      <td style={td({ maxWidth: '260px', wordBreak: 'break-word' })}>{f.title}</td>
      <td style={td()}><Badge value={f.severity} /></td>
      <td style={td({ color: MUTED, fontSize: '0.75rem' })}>{f.check_type || '—'}</td>
      <td style={td({ fontFamily: 'monospace', fontSize: '0.75rem', maxWidth: '200px', wordBreak: 'break-all' })}>{f.target || '—'}</td>
      <td style={td({ color: MUTED, fontSize: '0.75rem' })}>{fmtTime(f.discovered_at || f.created_at)}</td>
    </tr>
  );
}

function FindingSection({ title, findings }) {
  if (!findings || findings.length === 0) return null;
  return (
    <div style={{ marginBottom: '1.5rem' }}>
      <div style={{ fontSize: '0.85rem', fontWeight: 600, color: MUTED, marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        {title} ({findings.length})
      </div>
      <SectionTable
        columns={['Title', 'Severity', 'Check Type', 'Target', 'Discovered']}
        rows={findings}
        renderRow={f => <FindingRow f={f} />}
      />
    </div>
  );
}

function FindingsTab({ domainFindings, nmapFindings, otherFindings }) {
  const total = (domainFindings?.length || 0) + (nmapFindings?.length || 0) + (otherFindings?.length || 0);
  if (total === 0) {
    return <div style={{ color: MUTED, padding: '2rem', textAlign: 'center' }}>No findings recorded.</div>;
  }
  return (
    <div>
      <FindingSection title="Domain Security" findings={domainFindings} />
      <FindingSection title="Nmap / CVEs" findings={nmapFindings} />
      <FindingSection title="Other" findings={otherFindings} />
    </div>
  );
}

// ── main page ────────────────────────────────────────────────────────────────
export default function ScanDetailPage() {
  const uuid = window.location.pathname.split('/scans/')[1]?.replace(/\/$/, '');

  const { data: fullData, loading, error: fetchError, refetch } = useFetch('/scans/' + uuid + '/');

  // track previous status to detect completion
  const prevStatus = useRef(null);
  const [notification, setNotification] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [activeTab, setActiveTab] = useState('subdomains');

  const session   = fullData?.session;
  const scanIsActive = session?.status === 'pending' || session?.status === 'running';

  const { data: pollData, error: pollError } = usePolling(
    '/scans/' + uuid + '/status/',
    3000,
    scanIsActive,
  );

  // Detect when polling reports completion → refetch full data
  useEffect(() => {
    if (!pollData?.session) return;
    const newStatus = pollData.session.status;
    if (prevStatus.current && !TERMINAL.has(prevStatus.current) && TERMINAL.has(newStatus)) {
      setNotification({ message: `Scan ${newStatus}.`, type: newStatus === 'completed' ? 'success' : 'error' });
      refetch();
    }
    prevStatus.current = newStatus;
  }, [pollData, refetch]);

  // Merge live counts from polling into display data
  const vulnCounts   = pollData?.vuln_counts   || fullData?.vuln_counts   || {};
  const assetCounts  = pollData?.asset_counts  || fullData?.asset_counts  || {};
  const stepResults  = pollData?.step_results  || [];
  const liveStatus   = pollData?.session?.status || session?.status;

  // ── actions ──────────────────────────────────────────────────────────────
  async function handleStop() {
    try {
      await apiPost('/scans/' + uuid + '/stop/', {});
      setNotification({ message: 'Scan stop requested.', type: 'info' });
      refetch();
    } catch (e) {
      setActionError('Stop failed: ' + e.message);
    }
  }

  async function handleDelete() {
    try {
      await apiPost('/scans/' + uuid + '/delete/', {});
      navigate('/scans');
    } catch (e) {
      setActionError('Delete failed: ' + e.message);
    }
  }

  // ── render states ─────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh', background: BG }}>
        <Spinner size={40} />
      </div>
    );
  }

  if (fetchError) {
    return (
      <div style={{ padding: '2rem', color: '#f87171', background: BG, minHeight: '100vh' }}>
        Error loading scan: {fetchError}
      </div>
    );
  }

  if (!fullData) return null;

  const tabs = [
    { id: 'subdomains', label: `Subdomains (${fullData.subdomains?.length ?? 0})` },
    { id: 'ips',        label: `IPs (${fullData.ips?.length ?? 0})` },
    { id: 'ports',      label: `Ports (${fullData.ports?.length ?? 0})` },
    { id: 'urls',       label: `URLs (${fullData.urls?.length ?? 0})` },
    { id: 'findings',   label: `Findings (${(fullData.domain_findings?.length || 0) + (fullData.nmap_findings?.length || 0) + (fullData.other_findings?.length || 0)})` },
  ];

  return (
    <div style={{ background: BG, minHeight: '100vh', color: TEXT, fontFamily: 'system-ui, sans-serif', padding: '1.5rem 2rem' }}>

      {/* Notifications */}
      {notification && (
        <Notification key={notification.message} message={notification.message} type={notification.type} />
      )}

      {/* ── Header ── */}
      <div style={{ marginBottom: '1.5rem' }}>
        <button
          onClick={() => navigate('/scans')}
          style={{ background: 'none', border: 'none', color: MUTED, cursor: 'pointer', fontSize: '0.85rem', padding: 0, marginBottom: '1rem' }}
        >
          ← Back to Scans
        </button>

        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'flex-start', gap: '1rem', justifyContent: 'space-between' }}>
          <div>
            <h1 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 700, color: TEXT }}>
              {session?.domain_name || 'Scan Detail'}
            </h1>
            <div style={{ marginTop: '4px', display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center' }}>
              <span style={{ fontSize: '0.75rem', color: MUTED, fontFamily: 'monospace' }}>{uuid}</span>
              <Badge value={liveStatus || session?.status} />
              {session?.triggered_by && (
                <Badge value="info" label={session.triggered_by} />
              )}
              {session?.scan_type && (
                <span style={{ fontSize: '0.75rem', color: MUTED }}>• {session.scan_type}</span>
              )}
            </div>
            <div style={{ marginTop: '6px', fontSize: '0.78rem', color: MUTED }}>
              Started: {fmtTime(session?.start_time)}
              {session?.end_time && <> &nbsp;·&nbsp; Ended: {fmtTime(session.end_time)}</>}
              {session?.end_time && <> &nbsp;·&nbsp; Duration: {fmtDuration(session.start_time, session.end_time)}</>}
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
            {(liveStatus === 'pending' || liveStatus === 'running') && (
              <ConfirmButton
                onConfirm={handleStop}
                label="Stop Scan"
                confirmLabel="Confirm Stop"
                danger={true}
              />
            )}
            <ConfirmButton
              onConfirm={handleDelete}
              label="Delete"
              confirmLabel="Confirm Delete"
              danger={true}
            />
          </div>
        </div>

        {actionError && (
          <div style={{ marginTop: '0.5rem', color: '#f87171', fontSize: '0.85rem' }}>{actionError}</div>
        )}
      </div>

      {/* ── Live Progress (running/pending only) ── */}
      {(liveStatus === 'running' || liveStatus === 'pending') && stepResults.length > 0 && (
        <div style={{ ...card(), marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <Spinner size={16} />
            <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>Workflow Progress</span>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
              <thead>
                <tr>
                  {['Tool', 'Status', 'Findings', 'Started', 'Finished', 'Duration', 'Error'].map(h => (
                    <th key={h} style={th}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {stepResults.map((s, i) => <StepResultRow key={i} step={s} />)}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Vuln Summary Cards ── */}
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '1.5rem' }}>
        {['critical', 'high', 'medium', 'low'].map(sev => (
          <VulnCard key={sev} severity={sev} count={vulnCounts[sev]} />
        ))}
        <div style={{ ...card({ flex: '1 1 100px', textAlign: 'center' }) }}>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: MUTED }}>{vulnCounts.info ?? 0}</div>
          <div style={{ fontSize: '0.75rem', color: MUTED, marginTop: '2px' }}>Info</div>
        </div>
      </div>

      {/* ── Asset Count Row ── */}
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '1.5rem' }}>
        <AssetCountBadge
          label="Subdomains"
          value={assetCounts.subdomains_total}
          sub={assetCounts.subdomains_active != null ? `${assetCounts.subdomains_active} active` : null}
        />
        <AssetCountBadge label="IPs"    value={assetCounts.ips} />
        <AssetCountBadge label="Ports"  value={assetCounts.ports} />
        <AssetCountBadge label="URLs"   value={assetCounts.urls} />
        <AssetCountBadge label="Nmap Findings" value={assetCounts.nmap_findings} />
      </div>

      {/* ── Tabs ── */}
      <div style={card({ padding: 0, overflow: 'hidden' })}>
        {/* Tab bar */}
        <div style={{ display: 'flex', borderBottom: `1px solid ${BORDER}`, overflowX: 'auto' }}>
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                background: 'none',
                border: 'none',
                borderBottom: activeTab === tab.id ? `2px solid ${GREEN}` : '2px solid transparent',
                color: activeTab === tab.id ? GREEN : MUTED,
                padding: '0.75rem 1.25rem',
                cursor: 'pointer',
                fontSize: '0.85rem',
                fontWeight: activeTab === tab.id ? 600 : 400,
                whiteSpace: 'nowrap',
                marginBottom: '-1px',
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div style={{ padding: '1rem 1.25rem' }}>
          {activeTab === 'subdomains' && <SubdomainsTab subdomains={fullData.subdomains} />}
          {activeTab === 'ips'        && <IPsTab ips={fullData.ips} />}
          {activeTab === 'ports'      && <PortsTab ports={fullData.ports} />}
          {activeTab === 'urls'       && <URLsTab urls={fullData.urls} />}
          {activeTab === 'findings'   && (
            <FindingsTab
              domainFindings={fullData.domain_findings}
              nmapFindings={fullData.nmap_findings}
              otherFindings={fullData.other_findings}
            />
          )}
        </div>
      </div>

      {/* poll/fetch error footnote */}
      {(pollError || fetchError) && (
        <div style={{ marginTop: '0.75rem', fontSize: '0.78rem', color: '#f87171' }}>
          Polling error: {pollError || fetchError}
        </div>
      )}
    </div>
  );
}
