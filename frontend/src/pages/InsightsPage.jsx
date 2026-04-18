import React from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { useFetch } from '../hooks/useFetch.js';

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function KpiCard({ label, value, colorCls }) {
  return (
    <div className={`rounded-xl border p-5 text-center ${colorCls}`}>
      <div className="text-3xl font-bold leading-none mb-1">{value ?? 0}</div>
      <div className="text-xs font-semibold uppercase tracking-wider opacity-80 capitalize">{label}</div>
    </div>
  );
}

function DataTable({ title, subtitle, columns, rows, renderRow, emptyMsg = 'No data.' }) {
  return (
    <div className="bg-card border border-rim rounded-xl overflow-hidden mb-5">
      {(title || subtitle) && (
        <div className="px-4 py-3 border-b border-rim">
          {title    && <h2 className="text-lit text-sm font-semibold">{title}</h2>}
          {subtitle && <p className="text-dim text-xs mt-0.5">{subtitle}</p>}
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead><tr>{columns.map(c => <th key={c} className="tbl-th">{c}</th>)}</tr></thead>
          <tbody>
            {rows && rows.length > 0
              ? rows.map((row, i) => <tr key={i} className="hover:bg-hover transition-colors">{renderRow(row, i)}</tr>)
              : <tr><td colSpan={columns.length} className="tbl-td text-center text-dim py-8">{emptyMsg}</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const SEV_TEXT = { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-blue-400', info: 'text-gray-400' };

export default function InsightsPage() {
  const { data, loading, error } = useFetch('/insights/');

  if (loading) return <Layout><div className="flex justify-center items-center h-64"><Spinner size={40} /></div></Layout>;
  if (error)   return <Layout><div className="text-red-400 p-4">Error: {error}</div></Layout>;
  if (!data)   return <Layout><div /></Layout>;

  const {
    kpi_open_critical = 0, kpi_open_high = 0, kpi_new = 0, kpi_fixed = 0,
    scan_trend = [], delta_trend = [], top_hosts = [], top_finding_types = [],
    severity_distribution = {}, top_services = [], asset_growth = [],
  } = data;

  return (
    <Layout>
      <div className="space-y-6">
        <div>
          <h1 className="text-lit text-xl font-bold">Insights</h1>
          <p className="text-dim text-sm mt-0.5">Trends and security metrics across all scans</p>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <KpiCard label="Open Critical"   value={kpi_open_critical} colorCls="text-red-400 border-red-800 bg-red-900/10" />
          <KpiCard label="Open High"       value={kpi_open_high}     colorCls="text-orange-400 border-orange-800 bg-orange-900/10" />
          <KpiCard label="New This Scan"   value={kpi_new}           colorCls="text-brand border-brand/30 bg-brand/10" />
          <KpiCard label="Fixed This Scan" value={kpi_fixed}         colorCls="text-green-400 border-green-800 bg-green-900/10" />
        </div>

        {Object.keys(severity_distribution).length > 0 && (
          <DataTable
            title="Severity Distribution" subtitle="Open findings by severity"
            columns={['Severity', 'Count']}
            rows={Object.entries(severity_distribution).sort((a, b) => {
              const order = ['critical', 'high', 'medium', 'low', 'info'];
              return order.indexOf(a[0]) - order.indexOf(b[0]);
            })}
            renderRow={([sev, cnt]) => (
              <>
                <td className="tbl-td"><Badge value={sev} /></td>
                <td className={`tbl-td font-semibold ${SEV_TEXT[sev] || 'text-body'}`}>{cnt}</td>
              </>
            )}
          />
        )}

        <DataTable
          title="Scan Trend" subtitle="Finding counts per scan session"
          columns={['Scan', 'Critical', 'High', 'Medium', 'Low', 'Total']}
          rows={scan_trend} emptyMsg="No scan trend data yet."
          renderRow={row => (
            <>
              <td className="tbl-td text-lit font-medium">{row.label || '—'}</td>
              <td className={`tbl-td ${row.critical > 0 ? 'text-red-400 font-semibold' : 'text-dim'}`}>{row.critical ?? 0}</td>
              <td className={`tbl-td ${row.high > 0 ? 'text-orange-400 font-semibold' : 'text-dim'}`}>{row.high ?? 0}</td>
              <td className={`tbl-td ${row.medium > 0 ? 'text-yellow-400 font-semibold' : 'text-dim'}`}>{row.medium ?? 0}</td>
              <td className={`tbl-td ${row.low > 0 ? 'text-blue-400 font-semibold' : 'text-dim'}`}>{row.low ?? 0}</td>
              <td className="tbl-td text-body font-semibold">{row.total ?? 0}</td>
            </>
          )}
        />

        <DataTable
          title="Delta Trend" subtitle="New vs. removed findings per scan"
          columns={['Scan', 'New Findings', 'Removed Findings']}
          rows={delta_trend} emptyMsg="No delta data yet."
          renderRow={row => (
            <>
              <td className="tbl-td text-lit font-medium">{row.label || '—'}</td>
              <td className={`tbl-td ${row.new > 0 ? 'text-red-400 font-semibold' : 'text-dim'}`}>{row.new ?? 0}</td>
              <td className={`tbl-td ${row.removed > 0 ? 'text-brand font-semibold' : 'text-dim'}`}>{row.removed ?? 0}</td>
            </>
          )}
        />

        <DataTable
          title="Top Hosts by Findings"
          columns={['Domain', 'Finding Count']} rows={top_hosts} emptyMsg="No host data."
          renderRow={row => (
            <>
              <td className="tbl-td font-mono text-lit font-medium">{row.domain}</td>
              <td className="tbl-td text-brand font-semibold">{row.count}</td>
            </>
          )}
        />

        <DataTable
          title="Top Finding Types"
          columns={['Severity', 'Title', 'Check Type', 'Occurrences', 'Last Seen']}
          rows={top_finding_types} emptyMsg="No finding type data."
          renderRow={row => (
            <>
              <td className="tbl-td"><Badge value={row.severity} /></td>
              <td className="tbl-td text-lit font-medium max-w-xs truncate">{row.title}</td>
              <td className="tbl-td font-mono text-dim text-xs">{row.check_type || '—'}</td>
              <td className="tbl-td text-brand font-semibold">{row.occurrence_count}</td>
              <td className="tbl-td text-dim text-xs">{fmtDate(row.last_seen)}</td>
            </>
          )}
        />

        {top_services.length > 0 && (
          <DataTable
            title="Top Services (CVEs)"
            columns={['Service', 'Version', 'CVE Count', 'Max CVSS']} rows={top_services}
            renderRow={row => (
              <>
                <td className="tbl-td font-mono text-lit font-medium">{row.service || '—'}</td>
                <td className="tbl-td font-mono text-dim text-xs">{row.version || '—'}</td>
                <td className={`tbl-td ${row.cve_count > 0 ? 'text-red-400 font-semibold' : 'text-dim'}`}>{row.cve_count ?? 0}</td>
                <td className={`tbl-td font-semibold ${row.max_cvss >= 7 ? 'text-red-400' : row.max_cvss >= 4 ? 'text-yellow-400' : 'text-dim'}`}>
                  {row.max_cvss != null ? row.max_cvss.toFixed(1) : '—'}
                </td>
              </>
            )}
          />
        )}

        {asset_growth.length > 0 && (
          <DataTable
            title="Asset Growth" subtitle="Asset counts per scan"
            columns={['Scan', 'Subdomains', 'Active', 'IPs', 'Ports', 'URLs']} rows={asset_growth}
            renderRow={row => (
              <>
                <td className="tbl-td text-lit font-medium">{row.label || '—'}</td>
                <td className="tbl-td text-body">{row.subdomains ?? 0}</td>
                <td className="tbl-td text-brand">{row.active_subdomains ?? 0}</td>
                <td className="tbl-td text-body">{row.ips ?? 0}</td>
                <td className="tbl-td text-body">{row.ports ?? 0}</td>
                <td className="tbl-td text-body">{row.urls ?? 0}</td>
              </>
            )}
          />
        )}
      </div>
    </Layout>
  );
}
