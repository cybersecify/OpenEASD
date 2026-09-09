import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
import { toast } from '../components/Notification.jsx';
import { apiGet, apiPost } from '../api/client.js';
import { useQuery } from '@tanstack/react-query';

// The BYOK keys the credentials store manages. `field` matches the API payload key.
const KEYS = [
  { field: 'shodan_api_key',      label: 'Shodan API key',       help: 'Unlocks the paid Shodan host API. Without it, scans use the free keyless InternetDB tier.' },
  { field: 'hibp_api_key',        label: 'Have I Been Pwned key', help: 'Authoritative breach data via HIBP. Without it, breach_check uses the free keyless XposedOrNot catalog.' },
  { field: 'github_token',        label: 'GitHub token',          help: 'Raises GitHub API limits and enables org-scoped secret/recon search (github_recon, github_secrets).' },
  { field: 'github_secret',       label: 'GitHub secret',         help: 'Reserved — not currently consumed by a tool.' },
  { field: 'dns_history_api_url', label: 'DNS history API URL',   help: 'BYO passive-DNS endpoint for the dns_history tool. No-op if unset.' },
];

function sourceBadge(source) {
  // source: 'db' | 'env' | 'none'
  if (source === 'db')  return <Badge value="active"   label="Set (UI)" />;
  if (source === 'env') return <Badge value="info"     label="From env var" />;
  return <Badge value="inactive" label="Not set" />;
}

function KeyRow({ k, source, onSaved }) {
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);

  async function save(clear = false) {
    setBusy(true);
    try {
      await apiPost('/credentials/', { [k.field]: clear ? '' : value.trim() });
      toast.success(clear ? `${k.label} cleared.` : `${k.label} saved.`);
      setValue('');
      onSaved();
    } catch (err) {
      toast.error(err.message || `Failed to update ${k.label}.`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="border-b border-border py-4 last:border-0">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <span className="font-mono text-xs text-body">{k.label}</span>
        {sourceBadge(source)}
      </div>
      <p className="text-dim text-xs mt-1 mb-2">{k.help}</p>
      <div className="flex gap-2 flex-wrap">
        <input
          type="password"
          value={value}
          onChange={e => setValue(e.target.value)}
          placeholder="Enter value to set…"
          className="field flex-1 min-w-[200px]"
          autoComplete="new-password"
        />
        <Button onClick={() => save(false)} disabled={busy || !value.trim()}>Save</Button>
        <Button variant="outline" onClick={() => save(true)}
          disabled={busy || source !== 'db'}>Clear</Button>
      </div>
    </div>
  );
}

export default function CredentialsPage() {
  const { data, isLoading: loading, error, refetch } = useQuery({
    queryKey: ['/credentials/'],
    queryFn: () => apiGet('/credentials/'),
  });

  const source = data?.source ?? {};

  return (
    <Layout>
      <div className="space-y-5 max-w-3xl">
        <div>
          <h1 className="text-lit text-xl font-bold">Credentials</h1>
          <p className="text-dim text-sm mt-0.5">
            Bring-your-own-key API keys for the scanner tools. Keys entered here are stored
            encrypted and take effect on the next scan — no redeploy. A key set here overrides
            the matching environment variable; clear it to fall back to the env var.
          </p>
        </div>

        <Card>
          <CardHeader className="px-5 pt-4 pb-0"><CardTitle className="text-base">Tool API keys</CardTitle></CardHeader>
          <CardContent className="p-5 pt-2">
            {loading ? <div className="flex justify-center p-6"><Spinner /></div>
            : error   ? <div className="text-red-400 text-sm">Error: {error?.message ?? String(error)}</div>
            : KEYS.map(k => (
                <KeyRow key={k.field} k={k} source={source[k.field] ?? 'none'}
                  onSaved={refetch} />
              ))}
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-5 text-xs text-dim">
            <strong className="text-body">Values are never displayed.</strong> This page only
            shows whether each key is set and where it resolves from (UI, env var, or not set).
            Bootstrap secrets (<code>SECRET_KEY</code>, <code>FIELD_ENCRYPTION_KEY</code>,
            <code> DB_*</code>) are intentionally not managed here — they must stay environment
            variables because they bootstrap the encryption and database themselves.
          </CardContent>
        </Card>
      </div>
    </Layout>
  );
}
