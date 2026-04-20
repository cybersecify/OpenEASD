import React, { useState, useEffect } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { navigate } from '../App.jsx';
import { apiPost } from '../api/client.js';
import { useFetch } from '../hooks/useFetch.js';

export default function ScanStartPage() {
  const params     = new URLSearchParams(window.location.search);
  const initDomain = params.get('domain') || '';

  const { data: domainsData,   loading: ld } = useFetch('/domains/');
  const { data: workflowsData, loading: lw } = useFetch('/workflows/');

  const domains   = domainsData  || [];
  const workflows = workflowsData || [];
  const defaultWf = workflows.find(w => w.is_default);

  const [domain,     setDomain]    = useState(initDomain);
  const [workflowId, setWorkflow]  = useState('');
  const [scheduled,  setScheduled] = useState(false);
  const [schedTime,  setSchedTime] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error,      setError]     = useState(null);

  useEffect(() => {
    if (defaultWf && !workflowId) setWorkflow(String(defaultWf.id));
  }, [defaultWf]);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!domain) { setError('Select a domain.'); return; }
    setError(null); setSubmitting(true);
    try {
      const body = { domain, schedule_type: scheduled ? 'once' : 'now' };
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
          <div className="bg-card border border-rim rounded-xl p-6">
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs text-dim mb-1 font-medium">Domain *</label>
                <select value={domain} onChange={e => setDomain(e.target.value)} required className="field">
                  <option value="">— select domain —</option>
                  {domains.filter(d => d.is_active).map(d => (
                    <option key={d.id} value={d.name}>{d.name}</option>
                  ))}
                </select>
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
                <button type="submit" disabled={submitting} className="btn-primary">
                  {submitting ? 'Starting…' : scheduled ? 'Schedule Scan' : 'Start Scan Now'}
                </button>
                <button type="button" onClick={() => navigate('/scans')} className="btn-ghost">Cancel</button>
              </div>
            </form>
          </div>
        )}
      </div>
    </Layout>
  );
}
