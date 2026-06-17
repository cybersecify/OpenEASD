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

function SettingsCard({ config, onSaved }) {
  const [slack, setSlack]       = useState(config?.slack_webhook_url  ?? '');
  const [teams, setTeams]       = useState(config?.teams_webhook_url  ?? '');
  const [threshold, setThreshold] = useState(config?.severity_threshold ?? 'high');
  const [saving, setSaving]     = useState(false);
  const [testing, setTesting]   = useState(null); // 'slack' | 'teams' | null

  async function handleSave(e) {
    e.preventDefault();
    setSaving(true);
    try {
      await apiPost('/notifications/config/', {
        slack_webhook_url:  slack.trim(),
        teams_webhook_url:  teams.trim(),
        severity_threshold: threshold,
      });
      toast.success('Notification settings saved.');
      onSaved();
    } catch (err) {
      toast.error(err.message || 'Failed to save settings.');
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(channel) {
    setTesting(channel);
    try {
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
          {/* Slack */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-dim uppercase tracking-wider">Slack Incoming Webhook URL</label>
            <div className="flex gap-2">
              <input
                type="url"
                value={slack}
                onChange={e => setSlack(e.target.value)}
                placeholder="https://hooks.slack.com/services/…"
                className="field flex-1"
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => handleTest('slack')}
                disabled={!slack.trim() || testing === 'slack'}
              >
                {testing === 'slack' ? 'Sending…' : 'Test'}
              </Button>
            </div>
            <p className="text-xs text-dim">Create at <span className="font-mono">api.slack.com/apps</span> → Incoming Webhooks</p>
          </div>

          {/* Teams */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-dim uppercase tracking-wider">Microsoft Teams Webhook URL</label>
            <div className="flex gap-2">
              <input
                type="url"
                value={teams}
                onChange={e => setTeams(e.target.value)}
                placeholder="https://outlook.office.com/webhook/…"
                className="field flex-1"
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => handleTest('teams')}
                disabled={!teams.trim() || testing === 'teams'}
              >
                {testing === 'teams' ? 'Sending…' : 'Test'}
              </Button>
            </div>
            <p className="text-xs text-dim">Create via Power Automate → Post to a channel when a webhook request is received</p>
          </div>

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
            <div className="p-6 text-red-400 text-sm">Error: {alertsError}</div>
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
                  <Pagination page={page} totalPages={totalPages} onPageChange={setPage} />
                </div>
              )}
            </>
          )}
        </Card>
      </div>
    </Layout>
  );
}
