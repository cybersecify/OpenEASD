import React from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { navigate } from '../App.jsx';
import { useFetch } from '../hooks/useFetch.js';

function KpiCard({ label, value, colorCls }) {
  return (
    <div className={`rounded-xl border p-5 text-center ${colorCls}`}>
      <div className="text-3xl font-bold leading-none mb-1">{value ?? 0}</div>
      <div className="text-xs font-semibold uppercase tracking-wider opacity-80">{label}</div>
    </div>
  );
}

function AssetCard({ label, value }) {
  return (
    <div className="bg-card border border-rim rounded-xl p-4 text-center">
      <div className="text-2xl font-bold text-lit">{value ?? 0}</div>
      <div className="text-xs text-dim mt-0.5">{label}</div>
    </div>
  );
}

export default function DashboardPage() {
  const { data, loading, error } = useFetch('/dashboard/');

  if (loading) return <Layout><div className="flex justify-center items-center h-64"><Spinner size={40} /></div></Layout>;
  if (error)   return <Layout><div className="text-red-400 p-4">Error: {error}</div></Layout>;
  if (!data)   return <Layout><div /></Layout>;

  const {
    kpi_domains = 0, kpi_active_scans = 0, kpi_critical = 0, kpi_high = 0,
    kpi_subdomains = 0, kpi_ips = 0, kpi_ports = 0, kpi_urls = 0,
    domain_status = [], urgent_findings = [],
  } = data;

  return (
    <Layout>
      <div className="space-y-6">
        <div>
          <h1 className="text-lit text-xl font-bold">Dashboard</h1>
          <p className="text-dim text-sm mt-0.5">Attack surface overview</p>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <KpiCard label="Domains"       value={kpi_domains}      colorCls="text-body border-rim bg-card" />
          <KpiCard label="Running Scans" value={kpi_active_scans}  colorCls="text-brand border-brand/30 bg-brand/10" />
          <KpiCard label="Critical Open" value={kpi_critical}      colorCls="text-red-400 border-red-800 bg-red-900/10" />
          <KpiCard label="High Open"     value={kpi_high}          colorCls="text-orange-400 border-orange-800 bg-orange-900/10" />
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <AssetCard label="Subdomains" value={kpi_subdomains} />
          <AssetCard label="IPs"        value={kpi_ips} />
          <AssetCard label="Ports"      value={kpi_ports} />
          <AssetCard label="URLs"       value={kpi_urls} />
        </div>

        <div className="bg-card border border-rim rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-rim">
            <h2 className="text-lit text-sm font-semibold">Domain Status</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr>{['Domain', 'Status', 'Last Scan', 'Critical', 'High', 'Actions'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr>
              </thead>
              <tbody>
                {domain_status.length === 0 ? (
                  <tr><td colSpan={6} className="tbl-td text-center text-dim py-8">No domains yet.</td></tr>
                ) : domain_status.map(d => (
                  <tr key={d.id} className="hover:bg-hover transition-colors">
                    <td className="tbl-td text-lit font-mono font-medium">{d.domain}</td>
                    <td className="tbl-td"><Badge value={d.scan_status || 'idle'} /></td>
                    <td className="tbl-td text-dim">{d.last_scan ? new Date(d.last_scan).toLocaleDateString() : '—'}</td>
                    <td className="tbl-td text-red-400 font-semibold">{d.critical ?? 0}</td>
                    <td className="tbl-td text-orange-400 font-semibold">{d.high ?? 0}</td>
                    <td className="tbl-td">
                      <button onClick={() => navigate('/scans?domain=' + d.domain)} className="btn-ghost">View Scans</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {urgent_findings.length > 0 && (
          <div className="bg-card border border-rim rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-rim">
              <h2 className="text-lit text-sm font-semibold">Urgent Findings</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr>{['Severity', 'Title', 'Domain', 'Source'].map(h => <th key={h} className="tbl-th">{h}</th>)}</tr>
                </thead>
                <tbody>
                  {urgent_findings.map(f => (
                    <tr key={f.id} className="hover:bg-hover transition-colors">
                      <td className="tbl-td"><Badge value={f.severity} /></td>
                      <td className="tbl-td text-body font-medium max-w-xs truncate">{f.title}</td>
                      <td className="tbl-td text-dim font-mono text-xs">{f.domain}</td>
                      <td className="tbl-td text-dim text-xs">{f.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
