import React, { useState } from 'react';
import { Badge } from '../Badge.jsx';
import { Spinner } from '../Spinner.jsx';
import { Button } from '../ui/button.jsx';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card.jsx';
import { toast } from '../Notification.jsx';
import { apiGet, apiPost } from '../../api/client.js';
import { useQuery } from '@tanstack/react-query';

const PRIORITY_BADGE = {
  fix_now: 'critical',
  plan: 'medium',
  monitor: 'low',
  likely_noise: 'info',
};

function DecisionList({ decisions }) {
  const [open, setOpen] = useState(false);
  if (!decisions?.length) return null;
  return (
    <div className="border-t border-rim pt-3 mt-4">
      <button onClick={() => setOpen(o => !o)} className="text-xs text-dim hover:text-body">
        {open ? '▾' : '▸'} Scan decisions ({decisions.length})
      </button>
      {open && (
        <ul className="mt-2 space-y-1.5">
          {decisions.map((d, i) => (
            <li key={i} className="text-xs text-dim flex gap-2">
              <span className="font-mono shrink-0">#{d.iteration}</span>
              <span>
                <span className="text-body capitalize">{d.action.replace('_', ' ')}</span>
                {' '}<Badge value={d.status} />
                {d.rationale && <> — {d.rationale}</>}
                {d.denial_reason && <span className="text-red-400"> ({d.denial_reason})</span>}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * "Fix These First" panel on the scan detail page. Renders nothing while AI
 * is disabled, so the page is unchanged for non-AI deployments.
 */
export function TriagePanel({ uuid, scanRunning, onJumpToFinding }) {
  const [busy, setBusy] = useState(false);

  const { data: config } = useQuery({
    queryKey: ['/ai/config/'],
    queryFn: () => apiGet('/ai/config/'),
  });
  const aiEnabled = !!config?.enabled;

  const { data, refetch } = useQuery({
    queryKey: ['/ai/triage/', uuid],
    queryFn: () => apiGet(`/ai/triage/${uuid}/`),
    enabled: aiEnabled && !!uuid,
    refetchInterval: q => {
      const status = q.state.data?.status;
      return (status === 'running' || scanRunning) ? 3000 : false;
    },
  });

  if (!aiEnabled || !data || data.status === 'disabled') return null;

  async function handleRun() {
    setBusy(true);
    try {
      await apiPost(`/ai/triage/${uuid}/run/`, {});
      refetch();
    } catch (e) {
      toast.error(e.message || 'Failed to start triage.');
    } finally {
      setBusy(false);
    }
  }

  const triage = data.triage;

  return (
    <Card>
      <CardHeader className="border-b border-border px-5 py-4 flex flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle className="text-sm font-semibold">Fix These First</CardTitle>
          {triage && (
            <p className="text-xs text-dim mt-0.5">
              {triage.model} · {new Date(triage.generated_at).toLocaleString()} ·
              Machine-generated analysis — review before acting.
            </p>
          )}
        </div>
        {(data.status === 'complete' || data.status === 'failed') && !scanRunning && (
          <Button variant="outline" size="sm" onClick={handleRun} disabled={busy}>
            {data.status === 'failed' ? 'Retry' : 'Re-run triage'}
          </Button>
        )}
      </CardHeader>
      <CardContent className="px-5 py-4">
        {data.status === 'running' || (scanRunning && data.status === 'absent') ? (
          <div className="flex items-center gap-2 text-dim text-sm">
            <Spinner size={16} />
            {scanRunning ? 'Scan in progress — analysis runs when it finishes.' : 'Analyzing findings…'}
          </div>
        ) : data.status === 'failed' ? (
          <p className="text-sm text-red-400">{data.error}</p>
        ) : data.status === 'absent' ? (
          <div className="flex items-center gap-3">
            <p className="text-sm text-dim">No analysis for this scan yet.</p>
            <Button size="sm" onClick={handleRun} disabled={busy}>
              {busy ? 'Starting…' : 'Run triage'}
            </Button>
          </div>
        ) : (
          <>
            {triage.summary && <p className="text-sm text-body mb-4">{triage.summary}</p>}
            <ol className="space-y-2">
              {triage.items.map(item => (
                <li key={item.rank} className="flex gap-3 items-start">
                  <span className="font-mono text-dim text-sm shrink-0 w-6 text-right">{item.rank}.</span>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      {item.severity && <Badge value={item.severity} />}
                      <Badge value={PRIORITY_BADGE[item.priority] || 'info'} label={item.priority} />
                      {item.finding_id ? (
                        <button
                          onClick={() => onJumpToFinding?.(item.finding_id)}
                          className="text-brand hover:underline text-sm font-medium text-left"
                        >
                          {item.title}
                        </button>
                      ) : (
                        <span className="text-body text-sm font-medium">{item.title}</span>
                      )}
                      {item.target && <span className="font-mono text-xs text-dim">{item.target}</span>}
                    </div>
                    {item.rationale && <p className="text-xs text-dim mt-0.5">{item.rationale}</p>}
                  </div>
                </li>
              ))}
            </ol>
          </>
        )}
        <DecisionList decisions={data.decisions} />
      </CardContent>
    </Card>
  );
}
