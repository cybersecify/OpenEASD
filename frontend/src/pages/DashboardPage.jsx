import React from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
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

        <Card className="overflow-hidden">
          <CardHeader className="border-b border-border px-4 py-3">
            <CardTitle className="text-sm font-semibold">Domain Status</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    {['Domain', 'Status', 'Last Scan', 'Critical', 'High', 'Actions'].map(h => (
                      <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {domain_status.length === 0 ? (
                    <TableRow><TableCell colSpan={6} className="px-4 py-8 text-center text-dim">No domains yet.</TableCell></TableRow>
                  ) : domain_status.map(d => (
                    <TableRow key={d.id} className="hover:bg-hover transition-colors">
                      <TableCell className="px-4 py-3 text-lit font-mono font-medium">{d.domain}</TableCell>
                      <TableCell className="px-4 py-3"><Badge value={d.scan_status || 'idle'} /></TableCell>
                      <TableCell className="px-4 py-3 text-dim">{d.last_scan ? new Date(d.last_scan).toLocaleDateString() : '—'}</TableCell>
                      <TableCell className="px-4 py-3 text-red-400 font-semibold">{d.critical ?? 0}</TableCell>
                      <TableCell className="px-4 py-3 text-orange-400 font-semibold">{d.high ?? 0}</TableCell>
                      <TableCell className="px-4 py-3">
                        <Button variant="outline" size="sm" onClick={() => navigate('/scans?domain=' + d.domain)}>View Scans</Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {urgent_findings.length > 0 && (
          <Card className="overflow-hidden">
            <CardHeader className="border-b border-border px-4 py-3">
              <CardTitle className="text-sm font-semibold">Urgent Findings</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      {['Severity', 'Title', 'Domain', 'Source'].map(h => (
                        <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {urgent_findings.map(f => (
                      <TableRow key={f.id} className="hover:bg-hover transition-colors">
                        <TableCell className="px-4 py-3"><Badge value={f.severity} /></TableCell>
                        <TableCell className="px-4 py-3 text-body font-medium max-w-xs truncate">{f.title}</TableCell>
                        <TableCell className="px-4 py-3 text-dim font-mono text-xs">{f.domain}</TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs">{f.source}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </Layout>
  );
}
