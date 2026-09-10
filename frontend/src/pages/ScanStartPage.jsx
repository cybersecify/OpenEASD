import React, { useState, useEffect } from 'react';
import { Layout } from '../components/Layout.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Button } from '../components/ui/button.jsx';
import { Card, CardContent } from '../components/ui/card.jsx';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { apiPost, apiGet } from '../api/client.js';

// Mirrors the API's RFC 1123 hostname check (apps/core/data/domains/api.py)
const HOSTNAME_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

function enabledToolCount(wf) {
  if (!wf?.steps) return null;
  return wf.steps.filter(s => s.enabled).length;
}

function PresetCard({ active, onClick, title, desc, scope, auth }) {
  return (
    <button type="button" onClick={onClick}
      className={`flex-1 text-left rounded-xl border p-3.5 transition-colors
        ${active ? 'border-brand/50 bg-brand/10' : 'border-rim bg-canvas hover:border-dim'}`}>
      <div className="flex items-center gap-2">
        <span className={`h-3.5 w-3.5 rounded-full border-2 shrink-0
          ${active ? 'border-brand bg-brand' : 'border-dim'}`} />
        <span className={`text-sm font-semibold ${active ? 'text-brand' : 'text-body'}`}>{title}</span>
      </div>
      <div className="text-dim text-xs mt-1.5 leading-snug">{desc}</div>
      {scope && <div className="text-dim text-xs mt-1.5">{scope}</div>}
      <div className={`text-xs mt-1 font-medium ${auth.needed ? 'text-orange-400' : 'text-green-400'}`}>
        {auth.needed ? '⚠ Authorization required' : '✓ No authorization needed'}
      </div>
    </button>
  );
}

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
  const { data: toolsData } = useQuery({
    queryKey: ['/workflows/tools/'],
    queryFn: () => apiGet('/workflows/tools/'),
  });

  const domains   = domainsData  || [];
  const workflows = workflowsData || [];
  const allTools  = toolsData?.tools || [];
  const defaultWf = workflows.find(w => w.is_default);
  const passiveWf = workflows.find(w => w.name === 'Passive Scan')
                 || workflows.find(w => w.is_passive && !w.is_default);

  // Categories (phase_group) ordered by earliest phase — Domain Intelligence first.
  const categories = React.useMemo(() => {
    const byGroup = new Map();
    for (const t of allTools) {
      const g = t.phase_group || 'Other';
      if (!byGroup.has(g)) byGroup.set(g, { group: g, minPhase: t.phase ?? 99, tools: [] });
      const e = byGroup.get(g); e.tools.push(t); e.minPhase = Math.min(e.minPhase, t.phase ?? 99);
    }
    return [...byGroup.values()].sort((a, b) => a.minPhase - b.minPhase);
  }, [allTools]);

  const [scanType,   setScanType]  = useState('passive');   // 'passive' | 'full' | 'custom'
  const [customMode, setCustomMode] = useState('category'); // 'category' | 'workflow'
  const [selectedCats, setSelectedCats] = useState(['Domain Intelligence']);
  const [domain,     setDomain]    = useState(initDomain);
  const [workflowId, setWorkflow]  = useState('');
  const [scheduled,  setScheduled] = useState(false);
  const [schedTime,  setSchedTime] = useState('');
  const [attested,   setAttested]  = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error,      setError]     = useState(null);

  function toggleCat(g) {
    setSelectedCats(prev => prev.includes(g) ? prev.filter(x => x !== g) : [...prev, g]);
  }
  // Tools of the ticked categories → the subset a category scan will run.
  const selectedTools = allTools.filter(t => selectedCats.includes(t.phase_group));

  // If there's no passive workflow available, fall back to the full-scan preset.
  useEffect(() => {
    if (!lw && !passiveWf && scanType === 'passive') setScanType('full');
  }, [lw, passiveWf, scanType]);

  // Custom defaults its dropdown to the default workflow.
  useEffect(() => {
    if (scanType === 'custom' && defaultWf && !workflowId) setWorkflow(String(defaultWf.id));
  }, [scanType, defaultWf, workflowId]);

  // Resolve the preset → the workflow that will actually run (workflow-based paths).
  const resolvedWf =
    scanType === 'passive' ? passiveWf
    : scanType === 'full'  ? defaultWf
    : (workflows.find(w => String(w.id) === workflowId) || defaultWf);

  // Is the selection passive-only? Passive preset → yes; full → no; custom by
  // category → all selected tools passive; custom by workflow → the workflow's flag.
  const isCategoryScan = scanType === 'custom' && customMode === 'category';
  const selectionIsPassive =
    scanType === 'passive' ? true
    : scanType === 'full'  ? false
    : isCategoryScan       ? (selectedTools.length > 0 && selectedTools.every(t => !t.active))
    : !!resolvedWf?.is_passive;

  // Attestation is required unless the selection is passive-only AND runs now —
  // the exact condition the API's scan-start gate uses to bypass DomainAuthorization.
  const needsAttestation = !(selectionIsPassive && !scheduled);

  async function handleSubmit(e) {
    e.preventDefault();
    const target = domain.trim().toLowerCase();
    if (!target) { setError('Enter a domain.'); return; }
    if (!HOSTNAME_RE.test(target)) { setError('Enter a valid domain name.'); return; }
    if (isCategoryScan && selectedTools.length === 0) {
      setError('Select at least one category.');
      return;
    }
    if (needsAttestation && !attested) {
      setError('Please confirm you have authority to scan this domain.');
      return;
    }
    setError(null); setSubmitting(true);
    try {
      // One flow for new and existing domains: create if missing.
      let record;
      try {
        record = await apiPost('/domains/', { name: target });
      } catch (err) {
        if (err.status === 400) record = domains.find(d => d.name === target);
        if (!record) throw err;
      }
      // Only authorize when the scan actually needs it (active, or scheduled).
      // A passive-now scan is exempt from the gate, so we don't ask the user to attest.
      if (needsAttestation) {
        await apiPost(`/domains/${record.id}/authorize/`, { attestation: true });
      }

      const body = { domain: target, schedule_type: scheduled ? 'once' : 'now' };
      if (isCategoryScan && !scheduled) {
        // Category scan: run just the selected tools over the default workflow.
        body.tools = selectedTools.map(t => t.key);
      } else if (resolvedWf?.id) {
        body.workflow_id = Number(resolvedWf.id);
      }
      if (scheduled && schedTime) body.scheduled_at = schedTime;
      await apiPost('/scans/start/', body);
      navigate('/scans');
    } catch (err) {
      setError(err.data?.error?.message || err.message || 'Failed to start scan.');
    } finally { setSubmitting(false); }
  }

  const loading = ld || lw;
  const passiveScope = passiveWf ? `${enabledToolCount(passiveWf)} passive checks` : 'passive checks';
  const fullScope    = defaultWf ? `${enabledToolCount(defaultWf)} tools, all phases` : 'all tools';

  return (
    <Layout>
      <div className="max-w-2xl space-y-5">
        <div>
          <h1 className="text-lit text-xl font-bold">Start Scan</h1>
          <p className="text-dim text-sm mt-0.5">Launch a new scan against a domain</p>
        </div>
        {loading ? <div className="flex justify-center p-8"><Spinner /></div> : (
          <Card>
            <CardContent className="p-6">
              <form onSubmit={handleSubmit} className="space-y-5">
                <div>
                  <label className="block text-xs text-dim mb-1 font-medium">Domain *</label>
                  <input
                    type="text" value={domain} onChange={e => setDomain(e.target.value)}
                    placeholder="example.com" list="known-domains" className="field" autoFocus
                  />
                  <datalist id="known-domains">
                    {domains.map(d => <option key={d.id} value={d.name} />)}
                  </datalist>
                </div>

                <div>
                  <label className="block text-xs text-dim mb-2 font-medium">Scan type</label>
                  <div className="flex flex-col sm:flex-row gap-2.5">
                    <PresetCard
                      active={scanType === 'passive'} onClick={() => setScanType('passive')}
                      title="Passive recon"
                      desc="Public &amp; third-party data only — no packets to the target."
                      scope={passiveScope} auth={{ needed: false }}
                    />
                    <PresetCard
                      active={scanType === 'full'} onClick={() => setScanType('full')}
                      title="Full scan"
                      desc="Complete assessment — probes the target directly."
                      scope={fullScope} auth={{ needed: true }}
                    />
                    <PresetCard
                      active={scanType === 'custom'} onClick={() => setScanType('custom')}
                      title="Custom"
                      desc="Pick categories or a saved workflow."
                      scope={scanType === 'custom'
                        ? (isCategoryScan ? `${selectedTools.length} tools · ${selectedCats.length} categories`
                                          : `${enabledToolCount(resolvedWf)} tools`)
                        : ' '}
                      auth={{ needed: scanType === 'custom' ? needsAttestation : true }}
                    />
                  </div>
                </div>

                {scanType === 'custom' && (
                  <div className="space-y-3 rounded-lg border border-rim p-3">
                    <div className="inline-flex rounded-md border border-rim overflow-hidden text-xs">
                      {['category', 'workflow'].map(m => (
                        <button key={m} type="button" onClick={() => setCustomMode(m)}
                          className={`px-3 py-1 ${customMode === m ? 'bg-brand/15 text-brand' : 'text-dim hover:text-body'}`}>
                          {m === 'category' ? 'By category' : 'By workflow'}
                        </button>
                      ))}
                    </div>

                    {customMode === 'category' ? (
                      <div className="space-y-1.5">
                        {categories.map(({ group, tools }) => {
                          const activeCount = tools.filter(t => t.active).length;
                          return (
                            <label key={group} className="flex items-center gap-2 text-sm text-body cursor-pointer">
                              <input type="checkbox" checked={selectedCats.includes(group)}
                                onChange={() => toggleCat(group)} className="accent-brand" />
                              <span>{group}</span>
                              <span className="text-dim text-xs">
                                {tools.length} tools{activeCount === 0 ? ' · passive' : ''}
                              </span>
                            </label>
                          );
                        })}
                      </div>
                    ) : (
                      <select value={workflowId} onChange={e => setWorkflow(e.target.value)} className="field">
                        {workflows.map(w => (
                          <option key={w.id} value={w.id}>
                            {w.name}{w.is_default ? ' (default)' : ''}{w.is_passive ? ' · passive' : ''}
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                )}

                <label className="inline-flex items-center gap-2 text-sm text-body cursor-pointer">
                  <input type="checkbox" checked={scheduled} onChange={e => setScheduled(e.target.checked)} className="accent-brand" />
                  Schedule for later
                </label>
                {scheduled && (
                  <div>
                    <label className="block text-xs text-dim mb-1 font-medium">Scheduled time</label>
                    <input type="datetime-local" value={schedTime} onChange={e => setSchedTime(e.target.value)} className="field" />
                    <p className="text-dim text-xs mt-1">Scheduled scans always require authorization.</p>
                  </div>
                )}

                {needsAttestation ? (
                  <label className="flex items-start gap-2 text-sm text-body cursor-pointer rounded-lg border border-orange-800/50 bg-orange-900/10 p-3">
                    <input type="checkbox" checked={attested} onChange={e => setAttested(e.target.checked)} className="accent-brand mt-0.5" />
                    <span>I confirm I have authority to scan this domain (I own it or have written permission).</span>
                  </label>
                ) : (
                  <p className="text-green-400 text-sm rounded-lg border border-green-800/50 bg-green-900/10 p-3">
                    ✓ Passive scan — uses only public data, sends nothing to the target, and needs no authorization.
                  </p>
                )}

                {error && <p className="text-red-400 text-sm">{error}</p>}
                <div className="flex gap-3 pt-1">
                  <Button type="submit" disabled={submitting || !domain.trim() || (needsAttestation && !attested)}>
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
