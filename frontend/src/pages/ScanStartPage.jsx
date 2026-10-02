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

function PresetCard({ active, onClick, title, desc, scope, auth, tag }) {
  return (
    <button type="button" onClick={onClick}
      className={`flex-1 text-left rounded-xl border p-3.5 transition-colors
        ${active ? 'border-brand/50 bg-brand/10' : 'border-rim bg-canvas hover:border-dim'}`}>
      {tag && (
        <div className="text-[10px] uppercase tracking-wide text-dim mb-1.5 font-medium">{tag}</div>
      )}
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

// The four scan-mode cells, in matrix order (passive→active, light→deep).
// `title` is the quadrant name so the 2×2 reads consistently; `wfName` is the
// underlying predefined workflow it binds to by name (also shown as the muted
// eyebrow when it differs from the title). A cell whose workflow is absent
// (older DB) is omitted so the grid degrades gracefully.
const SCAN_MODE_DEFS = [
  { key: 'quick',        axis: 'passive', depth: 'light', wfName: 'Passive Scan Light',
    title: 'Passive Light', desc: 'Apex posture + credential exposure — a few checks, seconds.' },
  { key: 'passive',      axis: 'passive', depth: 'deep',  wfName: 'Passive Scan',
    title: 'Passive Deep', desc: 'Full passive sweep — public & third-party data only.' },
  { key: 'active_light', axis: 'active',  depth: 'light', wfName: 'Active Light',
    title: 'Active Light', desc: 'Discovery + quick config/exposure probes. Skips the slow engines.' },
  { key: 'full',         axis: 'active',  depth: 'deep',  wfName: 'Full Scan',
    title: 'Active Deep', desc: 'Complete assessment — every tool, all phases.' },
];

export function buildScanModes(workflows) {
  const byName = new Map((workflows || []).map(w => [w.name, w]));
  return SCAN_MODE_DEFS.flatMap(def => {
    const workflow = byName.get(def.wfName);
    if (!workflow) return [];
    return [{ ...def, workflow, needsAuth: !workflow.is_passive }];
  });
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

  const modes = React.useMemo(() => buildScanModes(workflows), [workflows]);

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

  const [scanType,   setScanType]  = useState('');          // mode key ('quick'|'passive'|'active_light'|'full') | 'custom'
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

  // Default selection, derived synchronously so the first painted frame already
  // shows a real mode (no one-frame "authorization required" flash): first
  // available of quick → passive → full, else custom. The user's explicit
  // choice (scanType) wins once set.
  const defaultScanKey = React.useMemo(() => {
    const byKey = Object.fromEntries(modes.map(m => [m.key, m]));
    return byKey.quick ? 'quick' : byKey.passive ? 'passive' : byKey.full ? 'full' : 'custom';
  }, [modes]);
  const effectiveScanType = scanType || defaultScanKey;

  // Custom defaults its dropdown to the default workflow.
  useEffect(() => {
    if (effectiveScanType === 'custom' && defaultWf && !workflowId) setWorkflow(String(defaultWf.id));
  }, [effectiveScanType, defaultWf, workflowId]);

  const selectedMode = modes.find(m => m.key === effectiveScanType);

  // Resolve the preset → the workflow that will actually run (workflow-based paths).
  const resolvedWf =
    effectiveScanType === 'custom' ? (workflows.find(w => String(w.id) === workflowId) || defaultWf)
    : selectedMode?.workflow;

  // Is the selection passive-only? Named cell → its needsAuth flag; custom by
  // category → all selected tools passive; custom by workflow → the workflow's flag.
  const isCategoryScan = effectiveScanType === 'custom' && customMode === 'category';
  const selectionIsPassive =
    effectiveScanType === 'custom' ? (isCategoryScan
      ? (selectedTools.length > 0 && selectedTools.every(t => !t.active))
      : !!resolvedWf?.is_passive)
    : !!selectedMode && !selectedMode.needsAuth;

  // Attestation is required unless the selection is passive-only AND runs now —
  // the exact condition the API's scan-start gate uses to bypass DomainAuthorization.
  const needsAttestation = !(selectionIsPassive && !scheduled);

  async function handleSubmit(e) {
    e.preventDefault();
    const target = domain.trim().toLowerCase();
    if (!target) { setError('Enter a domain.'); return; }
    if (!HOSTNAME_RE.test(target)) { setError('Enter a valid domain name.'); return; }
    if (effectiveScanType !== 'custom' && !selectedMode) {
      setError('Select a scan type.');
      return;
    }
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
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                    {modes.map(m => (
                      <PresetCard
                        key={m.key}
                        active={effectiveScanType === m.key} onClick={() => setScanType(m.key)}
                        tag={m.wfName !== m.title ? m.wfName : undefined}
                        title={m.title}
                        desc={m.desc}
                        scope={`${enabledToolCount(m.workflow)} tools`}
                        auth={{ needed: m.needsAuth }}
                      />
                    ))}
                  </div>
                  <div className="mt-2.5">
                    <PresetCard
                      active={effectiveScanType === 'custom'} onClick={() => setScanType('custom')}
                      title="Custom"
                      desc="Pick categories or a saved workflow."
                      scope={effectiveScanType === 'custom'
                        ? (isCategoryScan ? `${selectedTools.length} tools · ${selectedCats.length} categories`
                                          : `${enabledToolCount(resolvedWf)} tools`)
                        : ' '}
                      auth={{ needed: effectiveScanType === 'custom' ? needsAttestation : true }}
                    />
                  </div>
                </div>

                {effectiveScanType === 'custom' && (
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
