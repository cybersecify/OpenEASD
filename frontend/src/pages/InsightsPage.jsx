import React from 'react';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { useFetch } from '../hooks/useFetch.js';

// ── Shared tokens ────────────────────────────────────────────────────────────
const C = {
  bg:     '#0d1117',
  card:   '#161b22',
  border: '#30363d',
  text:   '#c9d1d9',
  muted:  '#8b949e',
  accent: '#30c074',
  danger: '#f87171',
};

const font = "'Segoe UI', system-ui, -apple-system, sans-serif";

const SEV_COLORS = {
  critical: '#dc2626',
  high:     '#ea580c',
  medium:   '#ca8a04',
  low:      '#2563eb',
  info:     '#6b7280',
};

function fmtDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  } catch { return iso; }
}

// ── Reusable table wrapper ───────────────────────────────────────────────────
function DataTable({ title, subtitle, columns, rows, renderRow, emptyMsg = 'No data.' }) {
  const th = {
    padding: '0.6rem 0.9rem',
    textAlign: 'left',
    color: C.muted,
    fontWeight: 600,
    fontSize: '0.75rem',
    letterSpacing: '0.04em',
    textTransform: 'uppercase',
    whiteSpace: 'nowrap',
    borderBottom: `1px solid ${C.border}`,
  };
  const tdBase = { padding: '0.6rem 0.9rem', verticalAlign: 'middle', fontSize: '0.85rem', color: C.text, borderBottom: `1px solid ${C.border}22` };

  return (
    <div style={{ backgroundColor: C.card, border: `1px solid ${C.border}`, borderRadius: '10px', overflow: 'hidden', marginBottom: '1.5rem' }}>
      {(title || subtitle) && (
        <div style={{ padding: '0.75rem 1rem', borderBottom: `1px solid ${C.border}` }}>
          {title  && <h2 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600, color: '#e6edf3' }}>{title}</h2>}
          {subtitle && <p style={{ margin: '0.15rem 0 0', fontSize: '0.8rem', color: C.muted }}>{subtitle}</p>}
        </div>
      )}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
          <thead>
            <tr>{columns.map(c => <th key={c} style={th}>{c}</th>)}</tr>
          </thead>
          <tbody>
            {rows && rows.length > 0
              ? rows.map((row, i) => (
                  <tr
                    key={i}
                    style={{ transition: 'background-color 0.1s' }}
                    onMouseEnter={e => e.currentTarget.style.backgroundColor = '#1c2128'}
                    onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
                  >
                    {renderRow(row, i, tdBase)}
                  </tr>
                ))
              : (
                <tr>
                  <td colSpan={columns.length} style={{ ...tdBase, textAlign: 'center', color: C.muted, padding: '1.5rem' }}>
                    {emptyMsg}
                  </td>
                </tr>
              )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── KPI card ────────────────────────────────────────────────────────────────
function KpiCard({ label, value, color, sub }) {
  const col = color || C.muted;
  return (
    <div style={{
      flex: '1 1 140px',
      background: col + '11',
      border: `1px solid ${col}44`,
      borderRadius: '8px',
      padding: '1.1rem 1.25rem',
      textAlign: 'center',
    }}>
      <div style={{ fontSize: '2rem', fontWeight: 700, color: col, lineHeight: 1 }}>{value ?? 0}</div>
      <div style={{ fontSize: '0.78rem', color: col, marginTop: '4px', textTransform: 'capitalize', fontWeight: 500 }}>{label}</div>
      {sub != null && <div style={{ fontSize: '0.72rem', color: C.muted, marginTop: '2px' }}>{sub}</div>}
    </div>
  );
}

// ── Page ────────────────────────────────────────────────────────────────────
export default function InsightsPage() {
  const { data, loading, error } = useFetch('/insights/');

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh', background: C.bg }}>
        <Spinner size={40} />
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ padding: '2rem', color: C.danger, background: C.bg, minHeight: '100vh', fontFamily: font }}>
        Error: {error}
      </div>
    );
  }

  if (!data) return null;

  const {
    kpi_open_critical = 0,
    kpi_open_high     = 0,
    kpi_new           = 0,
    kpi_fixed         = 0,
    scan_trend        = [],
    delta_trend       = [],
    top_hosts         = [],
    top_finding_types = [],
    severity_distribution = {},
    top_services      = [],
    asset_growth      = [],
  } = data;

  return (
    <div style={{ fontFamily: font, backgroundColor: C.bg, minHeight: '100vh', color: C.text, padding: '2rem', boxSizing: 'border-box' }}>

      {/* Header */}
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ margin: 0, fontSize: '1.4rem', fontWeight: 700, color: '#e6edf3' }}>Insights</h1>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.85rem', color: C.muted }}>
          Trends and security metrics across all scans
        </p>
      </div>

      {/* KPI row */}
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '1.75rem' }}>
        <KpiCard label="Open Critical"  value={kpi_open_critical} color={SEV_COLORS.critical} />
        <KpiCard label="Open High"      value={kpi_open_high}     color={SEV_COLORS.high} />
        <KpiCard label="New This Scan"  value={kpi_new}           color={C.accent} />
        <KpiCard label="Fixed This Scan" value={kpi_fixed}        color='#16a34a' />
      </div>

      {/* Severity distribution */}
      {Object.keys(severity_distribution).length > 0 && (
        <DataTable
          title="Severity Distribution"
          subtitle="Open findings by severity"
          columns={['Severity', 'Count']}
          rows={Object.entries(severity_distribution).sort((a, b) => {
            const order = ['critical', 'high', 'medium', 'low', 'info'];
            return order.indexOf(a[0]) - order.indexOf(b[0]);
          })}
          renderRow={([sev, cnt], _i, td) => (
            <>
              <td style={td}><Badge value={sev} /></td>
              <td style={{ ...td, fontWeight: 600, color: SEV_COLORS[sev] || C.text }}>{cnt}</td>
            </>
          )}
        />
      )}

      {/* Scan trend */}
      <DataTable
        title="Scan Trend"
        subtitle="Finding counts per scan session"
        columns={['Scan', 'Critical', 'High', 'Medium', 'Low', 'Total']}
        rows={scan_trend}
        emptyMsg="No scan trend data yet."
        renderRow={(row, _i, td) => (
          <>
            <td style={{ ...td, color: '#e6edf3', fontWeight: 500 }}>{row.label || '—'}</td>
            <td style={{ ...td, color: SEV_COLORS.critical, fontWeight: row.critical > 0 ? 600 : 400 }}>{row.critical ?? 0}</td>
            <td style={{ ...td, color: SEV_COLORS.high,     fontWeight: row.high > 0     ? 600 : 400 }}>{row.high     ?? 0}</td>
            <td style={{ ...td, color: SEV_COLORS.medium,   fontWeight: row.medium > 0   ? 600 : 400 }}>{row.medium   ?? 0}</td>
            <td style={{ ...td, color: SEV_COLORS.low,      fontWeight: row.low > 0      ? 600 : 400 }}>{row.low      ?? 0}</td>
            <td style={{ ...td, color: C.text, fontWeight: 600 }}>{row.total ?? 0}</td>
          </>
        )}
      />

      {/* Delta trend */}
      <DataTable
        title="Delta Trend"
        subtitle="New vs. removed findings per scan"
        columns={['Scan', 'New Findings', 'Removed Findings']}
        rows={delta_trend}
        emptyMsg="No delta data yet."
        renderRow={(row, _i, td) => (
          <>
            <td style={{ ...td, color: '#e6edf3', fontWeight: 500 }}>{row.label || '—'}</td>
            <td style={{ ...td, color: row.new > 0 ? C.danger : C.muted, fontWeight: row.new > 0 ? 600 : 400 }}>{row.new ?? 0}</td>
            <td style={{ ...td, color: row.removed > 0 ? C.accent : C.muted, fontWeight: row.removed > 0 ? 600 : 400 }}>{row.removed ?? 0}</td>
          </>
        )}
      />

      {/* Top hosts */}
      <DataTable
        title="Top Hosts by Findings"
        columns={['Domain', 'Finding Count']}
        rows={top_hosts}
        emptyMsg="No host data."
        renderRow={(row, _i, td) => (
          <>
            <td style={{ ...td, color: '#e6edf3', fontFamily: 'monospace', fontWeight: 500 }}>{row.domain}</td>
            <td style={{ ...td, color: C.accent, fontWeight: 600 }}>{row.count}</td>
          </>
        )}
      />

      {/* Top finding types */}
      <DataTable
        title="Top Finding Types"
        columns={['Severity', 'Title', 'Check Type', 'Occurrences', 'Last Seen']}
        rows={top_finding_types}
        emptyMsg="No finding type data."
        renderRow={(row, _i, td) => (
          <>
            <td style={td}><Badge value={row.severity} /></td>
            <td style={{ ...td, color: '#e6edf3', fontWeight: 500, maxWidth: '260px', wordBreak: 'break-word' }}>{row.title}</td>
            <td style={{ ...td, color: C.muted, fontFamily: 'monospace', fontSize: '0.78rem' }}>{row.check_type || '—'}</td>
            <td style={{ ...td, color: C.accent, fontWeight: 600 }}>{row.occurrence_count}</td>
            <td style={{ ...td, color: C.muted, fontSize: '0.78rem' }}>{fmtDate(row.last_seen)}</td>
          </>
        )}
      />

      {/* Top services */}
      {top_services.length > 0 && (
        <DataTable
          title="Top Services (CVEs)"
          columns={['Service', 'Version', 'CVE Count', 'Max CVSS']}
          rows={top_services}
          renderRow={(row, _i, td) => (
            <>
              <td style={{ ...td, color: '#e6edf3', fontFamily: 'monospace', fontWeight: 500 }}>{row.service || '—'}</td>
              <td style={{ ...td, color: C.muted, fontFamily: 'monospace', fontSize: '0.78rem' }}>{row.version || '—'}</td>
              <td style={{ ...td, color: row.cve_count > 0 ? C.danger : C.muted, fontWeight: row.cve_count > 0 ? 600 : 400 }}>{row.cve_count ?? 0}</td>
              <td style={{ ...td, color: row.max_cvss >= 7 ? C.danger : row.max_cvss >= 4 ? SEV_COLORS.medium : C.muted, fontWeight: row.max_cvss ? 600 : 400 }}>
                {row.max_cvss != null ? row.max_cvss.toFixed(1) : '—'}
              </td>
            </>
          )}
        />
      )}

      {/* Asset growth */}
      {asset_growth.length > 0 && (
        <DataTable
          title="Asset Growth"
          subtitle="Asset counts per scan"
          columns={['Scan', 'Subdomains', 'Active', 'IPs', 'Ports', 'URLs']}
          rows={asset_growth}
          renderRow={(row, _i, td) => (
            <>
              <td style={{ ...td, color: '#e6edf3', fontWeight: 500 }}>{row.label || '—'}</td>
              <td style={{ ...td, color: C.text }}>{row.subdomains ?? 0}</td>
              <td style={{ ...td, color: C.accent }}>{row.active_subdomains ?? 0}</td>
              <td style={{ ...td, color: C.text }}>{row.ips ?? 0}</td>
              <td style={{ ...td, color: C.text }}>{row.ports ?? 0}</td>
              <td style={{ ...td, color: C.text }}>{row.urls ?? 0}</td>
            </>
          )}
        />
      )}
    </div>
  );
}
