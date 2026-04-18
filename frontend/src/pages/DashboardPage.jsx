import React from 'react';
import { useFetch } from '../hooks/useFetch.js';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { navigate } from '../App.jsx';

// ── Shared tokens ────────────────────────────────────────────────────────────
const C = {
  bg:       '#0d1117',
  card:     '#161b22',
  border:   '#30363d',
  text:     '#c9d1d9',
  muted:    '#8b949e',
  accent:   '#30c074',
  critical: '#dc2626',
  high:     '#ea580c',
  danger:   '#f87171',
};

const font = "'Segoe UI', system-ui, -apple-system, sans-serif";

// ── Small helpers ─────────────────────────────────────────────────────────────
function Card({ children, style, onClick }) {
  return (
    <div
      onClick={onClick}
      style={{
        backgroundColor: C.card,
        border: `1px solid ${C.border}`,
        borderRadius: '10px',
        padding: '1.25rem 1.5rem',
        cursor: onClick ? 'pointer' : 'default',
        transition: onClick ? 'border-color 0.15s ease' : undefined,
        ...style,
      }}
      onMouseEnter={onClick ? e => e.currentTarget.style.borderColor = C.accent : undefined}
      onMouseLeave={onClick ? e => e.currentTarget.style.borderColor = C.border : undefined}
    >
      {children}
    </div>
  );
}

function SectionTitle({ children }) {
  return (
    <h2 style={{
      color: C.text,
      fontSize: '0.85rem',
      fontWeight: 600,
      letterSpacing: '0.06em',
      textTransform: 'uppercase',
      margin: '0 0 0.75rem',
      color: C.muted,
    }}>
      {children}
    </h2>
  );
}

function KpiCard({ label, value, color }) {
  return (
    <Card>
      <div style={{ color: color || C.text, fontSize: '2rem', fontWeight: 700, lineHeight: 1 }}>
        {value ?? '—'}
      </div>
      <div style={{ color: C.muted, fontSize: '0.8rem', marginTop: '0.4rem', fontWeight: 500 }}>
        {label}
      </div>
    </Card>
  );
}

function AssetCard({ label, value, onClick }) {
  return (
    <Card onClick={onClick}>
      <div style={{ color: C.accent, fontSize: '1.6rem', fontWeight: 700, lineHeight: 1 }}>
        {value ?? '—'}
      </div>
      <div style={{ color: C.muted, fontSize: '0.8rem', marginTop: '0.4rem', fontWeight: 500 }}>
        {label}
      </div>
    </Card>
  );
}

// Formats ISO date string to "Apr 17, 02:14" style
function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const { data, loading, error } = useFetch('/dashboard/');

  if (loading) return <div style={{ padding: '2rem' }}><Spinner /></div>;
  if (error) return <div style={{ padding: '2rem', color: C.danger }}>Error: {error}</div>;
  if (!data) return null;

  const { kpi, domain_status, urgent_findings, asset_counts, latest_scan_uuid } = data;

  return (
    <div style={{
      fontFamily: font,
      backgroundColor: C.bg,
      minHeight: '100vh',
      color: C.text,
      padding: '2rem',
      boxSizing: 'border-box',
    }}>
      {/* Page header */}
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ margin: 0, fontSize: '1.4rem', fontWeight: 700, color: '#e6edf3' }}>
          Dashboard
        </h1>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.85rem', color: C.muted }}>
          Attack surface overview
        </p>
      </div>

      {/* ── KPI row ── */}
      <SectionTitle>Key Metrics</SectionTitle>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '2rem' }}>
        <KpiCard label="Critical Findings" value={kpi?.critical} color={C.critical} />
        <KpiCard label="High Findings"     value={kpi?.high}     color={C.high} />
        <KpiCard label="Running Scans"     value={kpi?.running_scans} />
        <KpiCard label="Active Domains"    value={kpi?.active_domains} />
      </div>

      {/* ── Asset counts row ── */}
      <SectionTitle>Assets</SectionTitle>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '2rem' }}>
        <AssetCard
          label="Subdomains"
          value={asset_counts?.subdomains}
          onClick={latest_scan_uuid ? () => navigate(`/scans/${latest_scan_uuid}`) : undefined}
        />
        <AssetCard
          label="IP Addresses"
          value={asset_counts?.ips}
          onClick={latest_scan_uuid ? () => navigate(`/scans/${latest_scan_uuid}`) : undefined}
        />
        <AssetCard
          label="Open Ports"
          value={asset_counts?.ports}
          onClick={latest_scan_uuid ? () => navigate(`/scans/${latest_scan_uuid}`) : undefined}
        />
        <AssetCard
          label="URLs"
          value={asset_counts?.urls}
          onClick={latest_scan_uuid ? () => navigate(`/scans/${latest_scan_uuid}`) : undefined}
        />
      </div>

      {/* ── Domain status table ── */}
      <SectionTitle>Domain Status</SectionTitle>
      <div style={{
        backgroundColor: C.card,
        border: `1px solid ${C.border}`,
        borderRadius: '10px',
        overflow: 'hidden',
        marginBottom: '2rem',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              {['Domain', 'Last Scan', 'Status', 'Critical', 'High', 'Action'].map(h => (
                <th key={h} style={{
                  padding: '0.75rem 1rem',
                  textAlign: 'left',
                  color: C.muted,
                  fontWeight: 600,
                  fontSize: '0.78rem',
                  letterSpacing: '0.04em',
                  textTransform: 'uppercase',
                }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {domain_status && domain_status.length > 0 ? (
              domain_status.map((row, i) => {
                const { domain, summary, latest_session } = row;
                const uuid = latest_session?.uuid;
                return (
                  <tr
                    key={domain.id}
                    style={{
                      borderBottom: i < domain_status.length - 1 ? `1px solid ${C.border}` : 'none',
                    }}
                  >
                    <td style={{ padding: '0.75rem 1rem', color: '#e6edf3', fontWeight: 500 }}>
                      {domain.name}
                      {domain.is_primary && (
                        <span style={{
                          marginLeft: '0.5rem',
                          fontSize: '0.7rem',
                          color: C.accent,
                          fontWeight: 600,
                        }}>PRIMARY</span>
                      )}
                    </td>
                    <td style={{ padding: '0.75rem 1rem', color: C.muted }}>
                      {fmtDate(latest_session?.start_time)}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      {latest_session?.status
                        ? <Badge value={latest_session.status} />
                        : <span style={{ color: C.muted }}>—</span>
                      }
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      {summary?.critical_count != null
                        ? <span style={{ color: summary.critical_count > 0 ? C.critical : C.muted, fontWeight: summary.critical_count > 0 ? 700 : 400 }}>{summary.critical_count}</span>
                        : <span style={{ color: C.muted }}>—</span>
                      }
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      {summary?.high_count != null
                        ? <span style={{ color: summary.high_count > 0 ? C.high : C.muted, fontWeight: summary.high_count > 0 ? 700 : 400 }}>{summary.high_count}</span>
                        : <span style={{ color: C.muted }}>—</span>
                      }
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      {uuid ? (
                        <button
                          onClick={() => navigate(`/scans/${uuid}`)}
                          style={{
                            background: 'none',
                            border: `1px solid ${C.border}`,
                            borderRadius: '6px',
                            color: C.text,
                            cursor: 'pointer',
                            fontSize: '0.8rem',
                            padding: '0.3rem 0.75rem',
                            transition: 'border-color 0.15s ease, color 0.15s ease',
                          }}
                          onMouseEnter={e => { e.currentTarget.style.borderColor = C.accent; e.currentTarget.style.color = C.accent; }}
                          onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.text; }}
                        >
                          View Scan
                        </button>
                      ) : (
                        <span style={{ color: C.muted, fontSize: '0.8rem' }}>No scan</span>
                      )}
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan={6} style={{ padding: '2rem', textAlign: 'center', color: C.muted }}>
                  No domains configured.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* ── Urgent findings table ── */}
      <SectionTitle>Urgent Findings</SectionTitle>
      <div style={{
        backgroundColor: C.card,
        border: `1px solid ${C.border}`,
        borderRadius: '10px',
        overflow: 'hidden',
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              {['Severity', 'Title', 'Source', 'Target', 'Session'].map(h => (
                <th key={h} style={{
                  padding: '0.75rem 1rem',
                  textAlign: 'left',
                  color: C.muted,
                  fontWeight: 600,
                  fontSize: '0.78rem',
                  letterSpacing: '0.04em',
                  textTransform: 'uppercase',
                }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {urgent_findings && urgent_findings.length > 0 ? (
              urgent_findings.map((f, i) => (
                <tr
                  key={f.id}
                  onClick={() => navigate('/findings')}
                  style={{
                    borderBottom: i < urgent_findings.length - 1 ? `1px solid ${C.border}` : 'none',
                    cursor: 'pointer',
                    transition: 'background-color 0.1s ease',
                  }}
                  onMouseEnter={e => e.currentTarget.style.backgroundColor = '#1c2128'}
                  onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
                >
                  <td style={{ padding: '0.75rem 1rem' }}>
                    <Badge value={f.severity} />
                  </td>
                  <td style={{ padding: '0.75rem 1rem', color: '#e6edf3', maxWidth: '280px' }}>
                    <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {f.title}
                    </div>
                    {f.check_type && (
                      <div style={{ fontSize: '0.75rem', color: C.muted, marginTop: '0.1rem' }}>
                        {f.check_type}
                      </div>
                    )}
                  </td>
                  <td style={{ padding: '0.75rem 1rem', color: C.muted, fontSize: '0.82rem' }}>
                    {f.source}
                  </td>
                  <td style={{ padding: '0.75rem 1rem', color: C.muted, fontSize: '0.82rem', fontFamily: 'monospace' }}>
                    {f.target}
                  </td>
                  <td style={{ padding: '0.75rem 1rem' }}>
                    {f.session_id ? (
                      <button
                        onClick={e => { e.stopPropagation(); navigate(`/scans/${f.session_id}`); }}
                        style={{
                          background: 'none',
                          border: `1px solid ${C.border}`,
                          borderRadius: '6px',
                          color: C.muted,
                          cursor: 'pointer',
                          fontSize: '0.75rem',
                          padding: '0.25rem 0.6rem',
                          fontFamily: 'monospace',
                        }}
                        onMouseEnter={e => { e.currentTarget.style.borderColor = C.accent; e.currentTarget.style.color = C.accent; }}
                        onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.muted; }}
                      >
                        {String(f.session_id).slice(0, 8)}…
                      </button>
                    ) : '—'}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={5} style={{ padding: '2rem', textAlign: 'center', color: C.muted }}>
                  No urgent findings.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
