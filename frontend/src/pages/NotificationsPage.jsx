import React, { useState } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Pagination } from '../components/Pagination.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.jsx';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table.jsx';
import { toast } from '../components/Notification.jsx';
import { useNavigate } from 'react-router-dom';
import { apiPost, apiGet } from '../api/client.js';
import { useQuery } from '@tanstack/react-query';

const THRESHOLD_OPTIONS = [
  { label: 'Critical only',    value: 'critical' },
  { label: 'High and above',   value: 'high' },
  { label: 'Medium and above', value: 'medium' },
  { label: 'Low and above',    value: 'low' },
];

function sourceBadge(source) {
  // source: 'db' | 'env' | 'none'. Values are never returned by the API — this
  // only reflects whether a webhook is set and where it resolves from.
  if (source === 'db')  return <Badge value="active"   label="Set (UI)" />;
  if (source === 'env') return <Badge value="info"     label="From env var" />;
  return <Badge value="inactive" label="Not set" />;
}

function WebhookField({ label, placeholder, help, source, value, onChange, onTest, testing, onClear, busy }) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <label className="text-xs font-semibold text-dim uppercase tracking-wider">{label}</label>
        {sourceBadge(source)}
      </div>
      <div className="flex gap-2">
        <input
          type="url"
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={source === 'none' ? placeholder : 'Set — enter a new URL to replace'}
          className="field flex-1"
          autoComplete="off"
        />
        <Button type="button" variant="outline" size="sm" onClick={onTest}
          disabled={(source === 'none' && !value.trim()) || testing}>
          {testing ? 'Sending…' : 'Test'}
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={onClear}
          disabled={busy || source !== 'db'}>
          Clear
        </Button>
      </div>
      <p className="text-xs text-dim">{help}</p>
    </div>
  );
}

function SettingsCard({ config, onSaved }) {
  const [slack, setSlack]       = useState('');
  const [teams, setTeams]       = useState('');
  const [threshold, setThreshold] = useState(config?.severity_threshold ?? 'high');
  const [saving, setSaving]     = useState(false);
  const [testing, setTesting]   = useState(null); // 'slack' | 'teams' | null
  const slackSource = config?.slack_source ?? 'none';
  const teamsSource = config?.teams_source ?? 'none';

  async function handleSave(e) {
    e.preventDefault();
    setSaving(true);
    try {
      // Always send the threshold; send a webhook only when the user typed a new
      // one (omitted = unchanged server-side), so saving the threshold never
      // clobbers a stored URL we can't read back.
      const payload = { severity_threshold: threshold };
      if (slack.trim()) payload.slack_webhook_url = slack.trim();
      if (teams.trim()) payload.teams_webhook_url = teams.trim();
      await apiPost('/notifications/config/', payload);
      toast.success('Notification settings saved.');
      setSlack(''); setTeams('');
      onSaved();
    } catch (err) {
      toast.error(err.message || 'Failed to save settings.');
    } finally {
      setSaving(false);
    }
  }

  async function handleClear(channel) {
    setSaving(true);
    try {
      await apiPost('/notifications/config/', { [`${channel}_webhook_url`]: '' });
      toast.success(`${channel === 'slack' ? 'Slack' : 'Teams'} webhook cleared.`);
      channel === 'slack' ? setSlack('') : setTeams('');
      onSaved();
    } catch (err) {
      toast.error(err.message || `Failed to clear ${channel} webhook.`);
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(channel) {
    setTesting(channel);
    try {
      // The test endpoint uses the STORED webhook, so a configured channel can be
      // tested without re-entering the URL.
      await apiPost('/notifications/test/', { channel });
      toast.success(`Test ${channel === 'slack' ? 'Slack' : 'Teams'} message sent — check your channel.`);
    } catch (err) {
      toast.error(err.message || `Test failed for ${channel}.`);
    } finally {
      setTesting(null);
    }
  }

  return (
    <Card className="mb-5">
      <CardHeader className="border-b border-border px-5 py-4">
        <CardTitle className="text-sm font-semibold">Alert Settings</CardTitle>
      </CardHeader>
      <CardContent className="px-5 py-5">
        <form onSubmit={handleSave} className="space-y-5">
          <WebhookField
            label="Slack Incoming Webhook URL"
            placeholder="https://hooks.slack.com/services/…"
            help="Create at api.slack.com/apps → Incoming Webhooks. The stored URL is never displayed."
            source={slackSource}
            value={slack}
            onChange={setSlack}
            onTest={() => handleTest('slack')}
            testing={testing === 'slack'}
            onClear={() => handleClear('slack')}
            busy={saving}
          />
          <WebhookField
            label="Microsoft Teams Webhook URL"
            placeholder="https://outlook.office.com/webhook/…"
            help="Create via Power Automate → Post to a channel when a webhook request is received. The stored URL is never displayed."
            source={teamsSource}
            value={teams}
            onChange={setTeams}
            onTest={() => handleTest('teams')}
            testing={testing === 'teams'}
            onClear={() => handleClear('teams')}
            busy={saving}
          />

          {/* Threshold */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-dim uppercase tracking-wider">Minimum Severity to Alert</label>
            <select
              value={threshold}
              onChange={e => setThreshold(e.target.value)}
              className="field w-48"
            >
              {THRESHOLD_OPTIONS.map(o => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>

          <div className="flex gap-2 pt-1">
            <Button type="submit" disabled={saving}>
              {saving ? 'Saving…' : 'Save Settings'}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

function statusVariant(status) {
  return status === 'sent' ? 'active' : 'error';
}

export default function NotificationsPage() {
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const { data: config, isLoading: configLoading, refetch: refetchConfig } = useQuery({
    queryKey: ['/notifications/config/'],
    queryFn: () => apiGet('/notifications/config/'),
  });
  const { data: alerts, isLoading: alertsLoading, error: alertsError, refetch: refetchAlerts } = useQuery({
    queryKey: ['/notifications/alerts/', page],
    queryFn: () => apiGet(`/notifications/alerts/?page=${page}&page_size=25`),
  });

  const totalPages = alerts ? Math.ceil(alerts.count / alerts.page_size) : 1;

  return (
    <Layout>
      <div className="space-y-5">
        <div>
          <h1 className="text-lit text-xl font-bold">Notifications</h1>
          <p className="text-dim text-sm mt-0.5">Configure Slack and Teams alerts for new security findings</p>
        </div>

        {configLoading ? (
          <div className="flex justify-center p-8"><Spinner /></div>
        ) : (
          <SettingsCard config={config} onSaved={() => { refetchConfig(); refetchAlerts(); }} />
        )}

        {/* Alert History */}
        <Card className="overflow-hidden">
          <CardHeader className="border-b border-border px-5 py-4">
            <CardTitle className="text-sm font-semibold">Alert History</CardTitle>
          </CardHeader>
          {alertsLoading ? (
            <div className="flex justify-center p-8"><Spinner /></div>
          ) : alertsError ? (
            <div className="p-6 text-red-400 text-sm">Error: {alertsError?.message ?? String(alertsError)}</div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      {['Domain', 'Channel', 'Status', 'Threshold', 'Message', 'Sent'].map(h => (
                        <TableHead key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-dim whitespace-nowrap">{h}</TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {!alerts?.results?.length ? (
                      <TableRow>
                        <TableCell colSpan={6} className="px-4 py-10 text-center text-dim">
                          No alerts sent yet. Configure a webhook above and run a scan.
                        </TableCell>
                      </TableRow>
                    ) : alerts.results.map(a => (
                      <TableRow key={a.id} className="hover:bg-hover transition-colors">
                        <TableCell className="px-4 py-3 font-mono text-sm">
                          <button
                            onClick={() => navigate(`/scans/${a.session_uuid}`)}
                            className="text-brand hover:underline"
                          >
                            {a.domain}
                          </button>
                        </TableCell>
                        <TableCell className="px-4 py-3 text-dim capitalize">{a.alert_type}</TableCell>
                        <TableCell className="px-4 py-3">
                          <Badge value={a.status === 'sent' ? 'active' : 'failed'} />
                        </TableCell>
                        <TableCell className="px-4 py-3 text-dim capitalize">{a.severity_threshold}</TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs max-w-xs truncate" title={a.message}>
                          {a.message || (a.error_message ? `Error: ${a.error_message}` : '—')}
                        </TableCell>
                        <TableCell className="px-4 py-3 text-dim text-xs whitespace-nowrap">
                          {new Date(a.sent_at).toLocaleString()}
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
