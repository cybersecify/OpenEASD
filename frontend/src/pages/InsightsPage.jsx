import React from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
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
    <Card className="overflow-hidden mb-5">
      {(title || subtitle) && (
        <CardHeader className="border-b border-border px-4 py-3">
          {title    && <CardTitle className="text-sm font-semibold">{title}</CardTitle>}
          {subtitle && <p className="text-dim text-xs mt-0.5">{subtitle}</p>}
        </CardHeader>
      )}
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>{columns.map(c => <TableHead key={c} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{c}</TableHead>)}</TableRow>
            </TableHeader>
            <TableBody>
              {rows && rows.length > 0
                ? rows.map((row, i) => <TableRow key={i} className="hover:bg-hover transition-colors">{renderRow(row, i)}</TableRow>)
                : <TableRow><TableCell colSpan={columns.length} className="px-4 py-8 text-center text-dim">{emptyMsg}</TableCell></TableRow>}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
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
                <TableCell className="px-4 py-3"><Badge value={sev} /></TableCell>
                <TableCell className={`px-4 py-3 font-semibold ${SEV_TEXT[sev] || 'text-body'}`}>{cnt}</TableCell>
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
              <TableCell className="px-4 py-3 text-lit font-medium">{row.label || '—'}</TableCell>
              <TableCell className={`px-4 py-3 ${row.critical > 0 ? 'text-red-400 font-semibold' : 'text-dim'}`}>{row.critical ?? 0}</TableCell>
              <TableCell className={`px-4 py-3 ${row.high > 0 ? 'text-orange-400 font-semibold' : 'text-dim'}`}>{row.high ?? 0}</TableCell>
              <TableCell className={`px-4 py-3 ${row.medium > 0 ? 'text-yellow-400 font-semibold' : 'text-dim'}`}>{row.medium ?? 0}</TableCell>
              <TableCell className={`px-4 py-3 ${row.low > 0 ? 'text-blue-400 font-semibold' : 'text-dim'}`}>{row.low ?? 0}</TableCell>
              <TableCell className="px-4 py-3 text-body font-semibold">{row.total ?? 0}</TableCell>
            </>
          )}
        />

        <DataTable
          title="Delta Trend" subtitle="New vs. removed findings per scan"
          columns={['Scan', 'New Findings', 'Removed Findings']}
          rows={delta_trend} emptyMsg="No delta data yet."
          renderRow={row => (
            <>
              <TableCell className="px-4 py-3 text-lit font-medium">{row.label || '—'}</TableCell>
              <TableCell className={`px-4 py-3 ${row.new > 0 ? 'text-red-400 font-semibold' : 'text-dim'}`}>{row.new ?? 0}</TableCell>
              <TableCell className={`px-4 py-3 ${row.removed > 0 ? 'text-brand font-semibold' : 'text-dim'}`}>{row.removed ?? 0}</TableCell>
            </>
          )}
        />

        <DataTable
          title="Top Hosts by Findings"
          columns={['Domain', 'Finding Count']} rows={top_hosts} emptyMsg="No host data."
          renderRow={row => (
            <>
              <TableCell className="px-4 py-3 font-mono text-lit font-medium">{row.domain}</TableCell>
              <TableCell className="px-4 py-3 text-brand font-semibold">{row.count}</TableCell>
            </>
          )}
        />

        <DataTable
          title="Top Finding Types"
          columns={['Severity', 'Title', 'Check Type', 'Occurrences', 'Last Seen']}
          rows={top_finding_types} emptyMsg="No finding type data."
          renderRow={row => (
            <>
              <TableCell className="px-4 py-3"><Badge value={row.severity} /></TableCell>
              <TableCell className="px-4 py-3 text-lit font-medium max-w-xs truncate">{row.title}</TableCell>
              <TableCell className="px-4 py-3 font-mono text-dim text-xs">{row.check_type || '—'}</TableCell>
              <TableCell className="px-4 py-3 text-brand font-semibold">{row.occurrence_count}</TableCell>
              <TableCell className="px-4 py-3 text-dim text-xs">{fmtDate(row.last_seen)}</TableCell>
            </>
          )}
        />

        {top_services.length > 0 && (
          <DataTable
            title="Top Services (CVEs)"
            columns={['Service', 'Version', 'CVE Count', 'Max CVSS']} rows={top_services}
            renderRow={row => (
              <>
                <TableCell className="px-4 py-3 font-mono text-lit font-medium">{row.service || '—'}</TableCell>
                <TableCell className="px-4 py-3 font-mono text-dim text-xs">{row.version || '—'}</TableCell>
                <TableCell className={`px-4 py-3 ${row.cve_count > 0 ? 'text-red-400 font-semibold' : 'text-dim'}`}>{row.cve_count ?? 0}</TableCell>
                <TableCell className={`px-4 py-3 font-semibold ${row.max_cvss >= 7 ? 'text-red-400' : row.max_cvss >= 4 ? 'text-yellow-400' : 'text-dim'}`}>
                  {row.max_cvss != null ? row.max_cvss.toFixed(1) : '—'}
                </TableCell>
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
                <TableCell className="px-4 py-3 text-lit font-medium">{row.label || '—'}</TableCell>
                <TableCell className="px-4 py-3 text-body">{row.subdomains ?? 0}</TableCell>
                <TableCell className="px-4 py-3 text-brand">{row.active_subdomains ?? 0}</TableCell>
                <TableCell className="px-4 py-3 text-body">{row.ips ?? 0}</TableCell>
                <TableCell className="px-4 py-3 text-body">{row.ports ?? 0}</TableCell>
                <TableCell className="px-4 py-3 text-body">{row.urls ?? 0}</TableCell>
              </>
            )}
          />
        )}
      </div>
    </Layout>
  );
}
