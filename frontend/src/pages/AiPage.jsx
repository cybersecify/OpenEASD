import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Pagination } from '../components/Pagination.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import { toast } from '../components/Notification.jsx';
import { ConsentDialog } from '../components/ai/ConsentDialog.jsx';
import { useNavigate } from 'react-router-dom';
import { apiGet, apiPost } from '../api/client.js';
import { useQuery } from '@tanstack/react-query';

function CredPill({ set, label }) {
  return (
    <div className="flex items-center gap-2">
      <span className="font-mono text-xs text-body">{label}</span>
      <Badge value={set ? 'active' : 'inactive'} label={set ? 'Set' : 'Not set'} />
    </div>
  );
}

function SettingsCard({ config, onSaved }) {
  const [consentOpen, setConsentOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);

  async function post(body, okMessage) {
    setBusy(true);
    try {
      await apiPost('/ai/config/', body);
      toast.success(okMessage);
      onSaved();
    } catch (err) {
      toast.error(err.message || 'Failed to update AI settings.');
    } finally {
      setBusy(false);
      setConsentOpen(false);
    }
  }

  function handleToggle() {
    if (config.enabled) {
      post({ enabled: false }, 'Analysis disabled — no further calls will be made.');
    } else if (config.consent_current) {
      post({ enabled: true }, 'Analysis enabled.');
    } else {
      setConsentOpen(true); // toggle does not flip until consent is accepted
    }
  }

  async function handleTest() {
    setTesting(true);
    try {
      const res = await apiPost('/ai/test/', {});
      toast.success(`Connection OK — ${res.model} answered in ${res.latency_ms} ms.`);
    } catch (err) {
      toast.error(err.message || 'Connection test failed.');
    } finally {
      setTesting(false);
    }
  }

  return (
    <Card className="mb-5">
      <CardHeader className="border-b border-border px-5 py-4">
        <CardTitle className="text-sm font-semibold">Analysis Settings</CardTitle>
      </CardHeader>
      <CardContent className="px-5 py-5 space-y-5">
        {/* Credentials */}
        <div className="space-y-1.5">
          <label className="text-xs font-semibold text-dim uppercase tracking-wider">Cloudflare credentials</label>
          <div className="flex gap-6">
            <CredPill set={config.account_id_set} label="CLOUDFLARE_ACCOUNT_ID" />
            <CredPill set={config.api_token_set} label="CLOUDFLARE_API_TOKEN" />
          </div>
          <p className="text-xs text-dim">
            Credentials are read from environment variables only. They are never stored
            in the database or returned by the API. Set them in your <span className="font-mono">docker run -e</span> /
            compose file and restart.
          </p>
        </div>

        {/* Enable toggle */}
        <div className="space-y-1.5">
          <label className="text-xs font-semibold text-dim uppercase tracking-wider">Status</label>
          <div className="flex items-center gap-3">
            <Button
              onClick={handleToggle}
              disabled={busy || (!config.available && !config.enabled)}
              variant={config.enabled ? 'outline' : 'default'}
              size="sm"
              title={!config.available && !config.enabled ? 'Set both environment variables first' : undefined}
            >
              {config.enabled ? 'Disable analysis' : 'Enable analysis'}
            </Button>
            <Badge value={config.enabled ? 'active' : 'inactive'} label={config.enabled ? 'Enabled' : 'Disabled'} />
            <Button type="button" variant="outline" size="sm" onClick={handleTest}
                    disabled={!config.available || testing}>
              {testing ? 'Testing…' : 'Test connection'}
            </Button>
          </div>
          {config.consent_given && (
            <p className="text-xs text-dim">
              Consent given {config.consent_given_at ? new Date(config.consent_given_at).toLocaleString() : ''} ·
              turning this off stops all further calls.
            </p>
          )}
          <p className="text-xs text-dim">
            The connection test sends a fixed "reply OK" prompt — no scan data.
          </p>
        </div>

        {/* Read-only rows */}
        <div className="grid grid-cols-2 gap-4 max-w-xl">
          <div>
            <div className="text-xs font-semibold text-dim uppercase tracking-wider">Model</div>
            <div className="font-mono text-xs text-body mt-1">{config.model}</div>
          </div>
          <div>
            <div className="text-xs font-semibold text-dim uppercase tracking-wider">Findings per call limit</div>
            <div className="text-sm text-body mt-1">{config.max_findings_per_prompt}</div>
          </div>
        </div>

        <ConsentDialog
          open={consentOpen}
          accepting={busy}
          onAccept={() => post({ enabled: true, consent_accepted: true }, 'Analysis enabled.')}
          onCancel={() => setConsentOpen(false)}
        />
      </CardContent>
    </Card>
  );
}

export default function AiPage() {
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const { data: config, isLoading: configLoading, refetch: refetchConfig } = useQuery({
    queryKey: ['/ai/config/'],
    queryFn: () => apiGet('/ai/config/'),
  });
  const { data: audit, isLoading: auditLoading, error: auditError } = useQuery({
    queryKey: ['/ai/audit/', page],
    queryFn: () => apiGet(`/ai/audit/?page=${page}&page_size=25`),
  });

  const totalPages = audit ? Math.ceil(audit.count / audit.page_size) : 1;

  return (
    <Layout>
      <div className="space-y-5">
        <div>
          <h1 className="text-lit text-xl font-bold">AI Analysis</h1>
          <p className="text-dim text-sm mt-0.5">
            Ranks findings by exploitability, guides scan coverage, and writes report
            summaries — using Cloudflare Workers AI on your own account
          </p>
        </div>

        {configLoading || !config ? (
          <div className="flex justify-center p-8"><Spinner /></div>
        ) : (
          <SettingsCard config={config} onSaved={refetchConfig} />
        )}

        {/* Audit log */}
        <Card className="overflow-hidden">
          <CardHeader className="border-b border-border px-5 py-4">
            <CardTitle className="text-sm font-semibold">AI Call Log</CardTitle>
            <p className="text-xs text-dim mt-1">
              Every call to Cloudflare Workers AI is recorded here. Prompt and response
              contents are never stored.
            </p>
          </CardHeader>
          {auditLoading ? (
            <div className="flex justify-center p-8"><Spinner /></div>
          ) : auditError ? (
            <div className="p-6 text-red-400 text-sm">Error: {auditError?.message ?? String(auditError)}</div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      {['When', 'Domain', 'Purpose', 'Model', 'Tokens in/out', 'Findings', 'Status'].map(h => (
                        <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {!audit?.results?.length ? (
                      <TableRow>
                        <TableCell colSpan={7} className="px-4 py-10 text-center text-dim">
                          No calls yet — enable analysis above and run a scan.
                        </TableCell>
                      </TableRow>
                    ) : audit.results.map(row => (
                      <TableRow key={row.id} className="hover:bg-hover transition-colors">
                        <TableCell className="px-4 py-3 text-dim text-xs whitespace-nowrap">
                          {new Date(row.created_at).toLocaleString()}
                        </TableCell>
                        <TableCell className="px-4 py-3 font-mono text-sm">
                          {row.session_uuid ? (
                            <button onClick={() => navigate(`/scans/${row.session_uuid}`)}
                                    className="text-brand hover:underline">
                              {row.domain || row.session_uuid.slice(0, 8)}
                            </button>
                          ) : <span className="text-dim">—</span>}
                        </TableCell>
                        <TableCell className="px-4 py-3 text-dim capitalize">{row.purpose.replace('_', ' ')}</TableCell>
                        <TableCell className="px-4 py-3 font-mono text-xs text-dim max-w-48 truncate" title={row.model}>{row.model}</TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs whitespace-nowrap">
                          {row.tokens_in ?? '—'} / {row.tokens_out ?? '—'}
                        </TableCell>
                        <TableCell className="px-4 py-3 text-dim">{row.finding_count}</TableCell>
                        <TableCell className="px-4 py-3">
                          <Badge value={row.status === 'ok' ? 'active' : 'failed'} label={row.status} />
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
