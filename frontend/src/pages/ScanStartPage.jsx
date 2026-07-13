import React, { useState, useEffect } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent } from '../components/ui/card.jsx';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { apiPost, apiGet } from '../api/client.js';

// Mirrors the API's RFC 1123 hostname check (apps/core/domains/api.py)
const HOSTNAME_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export default function ScanStartPage() {
  const navigate = useNavigate();
  const params     = new URLSearchParams(window.location.search);
  const initDomain = params.get('domain') || '';

  const { data: domainsData,   isLoading: ld } = useQuery({
    queryKey: ['/domains/'],
    queryFn: () => apiGet('/domains/'),
  });
  const { data: workflowsData, isLoading: lw } = useQuery({
    queryKey: ['/workflows/'],
    queryFn: () => apiGet('/workflows/'),
  });

  const domains   = domainsData  || [];
  const workflows = workflowsData || [];
  const defaultWf = workflows.find(w => w.is_default);

  const [domain,     setDomain]    = useState(initDomain);
  const [workflowId, setWorkflow]  = useState('');
  const [scheduled,  setScheduled] = useState(false);
  const [schedTime,  setSchedTime] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error,      setError]     = useState(null);
  const [newDomainMode, setNewDomainMode] = useState(false);
  const [newDomain,     setNewDomain]     = useState('');
  const [attested,      setAttested]      = useState(false);

  useEffect(() => {
    if (defaultWf && !workflowId) setWorkflow(String(defaultWf.id));
  }, [defaultWf, workflowId]);

  async function handleSubmit(e) {
    e.preventDefault();
    const target = newDomainMode ? newDomain.trim().toLowerCase() : domain;
    if (!target) {
      setError(newDomainMode ? 'Enter a domain.' : 'Select a domain.');
      return;
    }
    if (newDomainMode) {
      if (!HOSTNAME_RE.test(target)) { setError('Enter a valid domain name.'); return; }
      if (!attested) {
        setError('Please confirm you have authority to scan this domain.');
        return;
      }
    }
    setError(null); setSubmitting(true);
    try {
      if (newDomainMode) {
        let created;
        try {
          created = await apiPost('/domains/', { name: target });
        } catch (err) {
          // Domain already exists — reuse the one from the loaded list.
          if (err.status === 400) created = domains.find(d => d.name === target);
          if (!created) throw err;
        }
        await apiPost(`/domains/${created.id}/authorize/`, { attestation: true });
      }
      const body = { domain: target, schedule_type: scheduled ? 'once' : 'now' };
      if (workflowId) body.workflow_id = Number(workflowId);
      if (scheduled && schedTime) body.scheduled_at = schedTime;
      await apiPost('/scans/start/', body);
      navigate('/scans');
    } catch (err) {
      setError(err.data?.error?.message || err.message || 'Failed to start scan.');
    } finally { setSubmitting(false); }
  }

  const loading = ld || lw;

  return (
    <Layout>
      <div className="max-w-lg space-y-5">
        <div>
          <h1 className="text-lit text-xl font-bold">Start Scan</h1>
          <p className="text-dim text-sm mt-0.5">Launch a new scan against a domain</p>
        </div>
        {loading ? <div className="flex justify-center p-8"><Spinner /></div> : (
          <Card>
            <CardContent className="p-6">
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="block text-xs text-dim font-medium">Domain *</label>
                    <button
                      type="button"
                      className="text-xs text-brand hover:underline"
                      onClick={() => { setNewDomainMode(m => !m); setError(null); }}
                    >
                      {newDomainMode ? 'Pick existing domain' : '＋ Scan a new domain'}
                    </button>
                  </div>
                  {newDomainMode ? (
                    <>
                      <input
                        type="text"
                        value={newDomain}
                        onChange={e => setNewDomain(e.target.value)}
                        placeholder="example.com"
                        className="field"
                        autoFocus
                      />
                      <label className="mt-2 flex items-start gap-2 text-sm text-body cursor-pointer">
                        <input
                          type="checkbox"
                          checked={attested}
                          onChange={e => setAttested(e.target.checked)}
                          className="accent-brand mt-0.5"
                        />
                        <span>I confirm I have authority to scan this domain (I own it or have written permission).</span>
                      </label>
                    </>
                  ) : (
                    <select value={domain} onChange={e => setDomain(e.target.value)} className="field">
                      <option value="">— select domain —</option>
                      {domains.filter(d => d.is_active && d.authorization).map(d => (
                        <option key={d.id} value={d.name}>{d.name}</option>
                      ))}
                    </select>
                  )}
                </div>
                <div>
                  <label className="block text-xs text-dim mb-1 font-medium">Workflow</label>
                  <select value={workflowId} onChange={e => setWorkflow(e.target.value)} className="field">
                    <option value="">— use default —</option>
                    {workflows.map(w => (
                      <option key={w.id} value={w.id}>{w.name}{w.is_default ? ' (default)' : ''}</option>
                    ))}
                  </select>
                </div>
                <label className="inline-flex items-center gap-2 text-sm text-body cursor-pointer">
                  <input type="checkbox" checked={scheduled} onChange={e => setScheduled(e.target.checked)} className="accent-brand" />
                  Schedule for later
                </label>
                {scheduled && (
                  <div>
                    <label className="block text-xs text-dim mb-1 font-medium">Scheduled time</label>
                    <input type="datetime-local" value={schedTime} onChange={e => setSchedTime(e.target.value)} className="field" />
                  </div>
                )}
                {error && <p className="text-red-400 text-sm">{error}</p>}
                <div className="flex gap-3 pt-1">
                  <Button
                    type="submit"
                    disabled={submitting || (newDomainMode && (!newDomain.trim() || !attested))}
                  >
                    {submitting ? 'Starting…' : scheduled ? 'Schedule Scan' : 'Start Scan Now'}
                  </Button>
                  <Button type="button" variant="outline" onClick={() => navigate('/scans')}>Cancel</Button>
                </div>
              </form>
            </CardContent>
          </Card>
        )}
      </div>
    </Layout>
  );
}
