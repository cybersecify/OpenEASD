import React, { useState, useEffect, useCallback } from 'react';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Notification } from '../components/Notification.jsx';
import { navigate } from '../App.jsx';
import { apiFetch, apiPost } from '../api/client.js';

// ── Shared tokens ────────────────────────────────────────────────────────────
const C = {
  bg:     '#0d1117',
  card:   '#161b22',
  border: '#30363d',
  text:   '#c9d1d9',
  muted:  '#8b949e',
  accent: '#30c074',
  danger: '#f87171',
};

const font = "'Segoe UI', system-ui, -apple-system, sans-serif";

function fmtDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch { return iso; }
}

function fmtDuration(start, end) {
  if (!start || !end) return '—';
  const ms = new Date(end) - new Date(start);
  if (ms < 0) return '—';
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

const th = {
  padding: '0.6rem 0.9rem',
  textAlign: 'left',
  color: C.muted,
  fontWeight: 600,
  fontSize: '0.75rem',
  letterSpacing: '0.04em',
  textTransform: 'uppercase',
  whiteSpace: 'nowrap',
  borderBottom: `1px solid ${C.border}`,
};

const td = (extra = {}) => ({
  padding: '0.6rem 0.9rem',
  verticalAlign: 'middle',
  fontSize: '0.85rem',
  color: C.text,
  borderBottom: `1px solid ${C.border}22`,
  ...extra,
});

export default function WorkflowDetailPage() {
  const id = window.location.pathname.replace(/^\/workflows\//, '').replace(/\/$/, '');

  const [fullData, setFullData]     = useState(null);
  const [loading, setLoading]       = useState(true);
  const [fetchErr, setFetchErr]     = useState(null);
  const [notification, setNotify]   = useState(null);

  // Editable fields
  const [name, setName]           = useState('');
  const [description, setDesc]    = useState('');
  const [isDefault, setIsDefault] = useState(false);
  const [enabledTools, setEnabled]= useState(new Set());
  const [saving, setSaving]       = useState(false);
  const [saveErr, setSaveErr]     = useState(null);
  const [togglingTool, setToggling] = useState(null);

  const fetchDetail = useCallback(async () => {
    setLoading(true);
    setFetchErr(null);
    try {
      const res = await apiFetch(`/workflows/${id}/`, { method: 'GET' });
      const d = res.data;
      setFullData(d);
      setName(d.workflow?.name || '');
      setDesc(d.workflow?.description || '');
      setIsDefault(d.workflow?.is_default || false);
      const enabled = new Set(
        (d.tool_steps || []).filter(s => s.enabled).map(s => s.key)
      );
      setEnabled(enabled);
    } catch (e) {
      setFetchErr(e.message);
      if (e.status === 401) window.location.href = '/login';
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { fetchDetail(); }, [fetchDetail]);

  function notify(message, type = 'success') {
    setNotify({ message, type, key: Date.now() });
  }

  async function handleSave(e) {
    e.preventDefault();
    if (!name.trim()) { setSaveErr('Name is required.'); return; }
    setSaving(true);
    setSaveErr(null);
    try {
      await apiPost(`/workflows/${id}/update/`, {
        name: name.trim(),
        description: description.trim(),
        is_default: isDefault,
        tools: [...enabledTools],
      });
      notify('Workflow saved.');
      fetchDetail();
    } catch (e) {
      setSaveErr(e.message);
    } finally {
      setSaving(false);
    }
  }

  async function handleToggleTool(toolKey) {
    setToggling(toolKey);
    try {
      const res = await apiPost(`/workflows/${id}/steps/${toolKey}/toggle/`);
      // Optimistic update from server response
      setEnabled(prev => {
        const next = new Set(prev);
        if (res.data?.enabled) next.add(toolKey); else next.delete(toolKey);
        return next;
      });
    } catch (e) {
      notify(e.message || 'Toggle failed.', 'error');
    } finally {
      setToggling(null);
    }
  }

  // ── render states ─────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh', background: C.bg }}>
        <Spinner size={40} />
      </div>
    );
  }

  if (fetchErr) {
    return (
      <div style={{ padding: '2rem', color: C.danger, background: C.bg, minHeight: '100vh' }}>
        Error: {fetchErr}
      </div>
    );
  }

  if (!fullData) return null;

  const { workflow, tool_steps = [], tool_requires = {}, recent_runs = [] } = fullData;

  const inputStyle = {
    background: C.bg,
    border: `1px solid ${C.border}`,
    borderRadius: '6px',
    color: C.text,
    fontSize: '0.875rem',
    padding: '0.4rem 0.75rem',
    outline: 'none',
    width: '100%',
    boxSizing: 'border-box',
  };

  return (
    <div style={{ fontFamily: font, backgroundColor: C.bg, minHeight: '100vh', color: C.text, padding: '2rem', boxSizing: 'border-box' }}>

      {notification && (
        <Notification key={notification.key} message={notification.message} type={notification.type} />
      )}

      {/* Back link */}
      <button
        onClick={() => navigate('/workflows')}
        style={{ background: 'none', border: 'none', color: C.muted, cursor: 'pointer', fontSize: '0.85rem', padding: 0, marginBottom: '1.25rem' }}
      >
        ← Back to Workflows
      </button>

      {/* Header */}
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ margin: 0, fontSize: '1.4rem', fontWeight: 700, color: '#e6edf3' }}>
          {workflow?.name || 'Workflow'}
        </h1>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.85rem', color: C.muted }}>
          {workflow?.description || 'No description.'}
          {workflow?.is_default && (
            <span style={{ marginLeft: '0.5rem', color: C.accent, fontWeight: 600 }}>• Default</span>
          )}
        </p>
      </div>

      {/* ── Edit form ── */}
      <div style={{ backgroundColor: C.card, border: `1px solid ${C.border}`, borderRadius: '10px', padding: '1.25rem', marginBottom: '1.5rem' }}>
        <h2 style={{ margin: '0 0 1rem', fontSize: '1rem', fontWeight: 600, color: '#e6edf3' }}>Edit Workflow</h2>
        <form onSubmit={handleSave}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '0.75rem' }}>
            <div>
              <label style={{ fontSize: '0.8rem', color: C.muted, display: 'block', marginBottom: '0.3rem' }}>Name *</label>
              <input value={name} onChange={e => setName(e.target.value)} style={inputStyle}
                onFocus={e => e.currentTarget.style.borderColor = C.accent}
                onBlur={e => e.currentTarget.style.borderColor = C.border}
              />
            </div>
            <div>
              <label style={{ fontSize: '0.8rem', color: C.muted, display: 'block', marginBottom: '0.3rem' }}>Description</label>
              <input value={description} onChange={e => setDesc(e.target.value)} style={inputStyle}
                onFocus={e => e.currentTarget.style.borderColor = C.accent}
                onBlur={e => e.currentTarget.style.borderColor = C.border}
              />
            </div>
          </div>

          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85rem', color: C.text, cursor: 'pointer' }}>
              <input type="checkbox" checked={isDefault} onChange={e => setIsDefault(e.target.checked)} style={{ accentColor: C.accent }} />
              Set as default workflow
            </label>
          </div>

          {/* Tool selection checkboxes */}
          {tool_steps.length > 0 && (
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ fontSize: '0.8rem', color: C.muted, display: 'block', marginBottom: '0.5rem' }}>Tools</label>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {tool_steps.map(step => {
                  const on = enabledTools.has(step.key);
                  const deps = tool_requires[step.key] || [];
                  return (
                    <label key={step.key} style={{
                      display: 'inline-flex', alignItems: 'center', gap: '0.35rem',
                      background: on ? C.accent + '22' : C.bg,
                      border: `1px solid ${on ? C.accent + '66' : C.border}`,
                      borderRadius: '6px',
                      padding: '0.3rem 0.65rem',
                      fontSize: '0.8rem',
                      color: on ? C.accent : C.text,
                      cursor: 'pointer',
                      transition: 'all 0.15s',
                    }}
                      title={deps.length ? `Requires: ${deps.join(', ')}` : undefined}
                    >
                      <input
                        type="checkbox"
                        checked={on}
                        onChange={() => {
                          setEnabled(prev => {
                            const next = new Set(prev);
                            if (on) next.delete(step.key); else next.add(step.key);
                            return next;
                          });
                        }}
                        style={{ accentColor: C.accent }}
                      />
                      {step.label || step.key}
                      {deps.length > 0 && <span style={{ color: C.muted, fontSize: '0.7rem' }}>*</span>}
                    </label>
                  );
                })}
              </div>
              {Object.keys(tool_requires).length > 0 && (
                <p style={{ margin: '0.4rem 0 0', fontSize: '0.75rem', color: C.muted }}>* has dependencies on other tools</p>
              )}
            </div>
          )}

          {saveErr && <div style={{ color: C.danger, fontSize: '0.82rem', marginBottom: '0.75rem' }}>{saveErr}</div>}

          <button
            type="submit"
            disabled={saving}
            style={{
              background: C.accent, border: 'none', borderRadius: '6px',
              color: '#0d1117', cursor: saving ? 'default' : 'pointer',
              fontSize: '0.875rem', fontWeight: 600, padding: '0.5rem 1.25rem',
              opacity: saving ? 0.7 : 1, transition: 'opacity 0.15s',
            }}
          >
            {saving ? 'Saving…' : 'Save Changes'}
          </button>
        </form>
      </div>

      {/* ── Tool steps (individual toggles) ── */}
      <div style={{ backgroundColor: C.card, border: `1px solid ${C.border}`, borderRadius: '10px', overflow: 'hidden', marginBottom: '1.5rem' }}>
        <div style={{ padding: '0.75rem 1rem', borderBottom: `1px solid ${C.border}` }}>
          <h2 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600, color: '#e6edf3' }}>Tool Steps</h2>
          <p style={{ margin: '0.2rem 0 0', fontSize: '0.8rem', color: C.muted }}>Toggle individual tools without saving the full form</p>
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
          <thead>
            <tr>
              {['Tool', 'Enabled', 'Requires', 'Quick Toggle'].map(h => (
                <th key={h} style={th}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {tool_steps.length > 0 ? (
              tool_steps.map((step, i) => {
                const on = enabledTools.has(step.key);
                const deps = tool_requires[step.key] || [];
                const toggling = togglingTool === step.key;
                return (
                  <tr
                    key={step.key}
                    style={{ borderBottom: i === tool_steps.length - 1 ? 'none' : `1px solid ${C.border}22` }}
                    onMouseEnter={e => e.currentTarget.style.backgroundColor = '#1c2128'}
                    onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
                  >
                    <td style={td({ color: '#e6edf3', fontWeight: 500 })}>{step.label || step.key}</td>
                    <td style={td()}>
                      {on
                        ? <span style={{ color: C.accent, fontWeight: 600, fontSize: '0.8rem' }}>Enabled</span>
                        : <span style={{ color: C.muted, fontSize: '0.8rem' }}>Disabled</span>}
                    </td>
                    <td style={td({ color: C.muted, fontFamily: 'monospace', fontSize: '0.78rem' })}>
                      {deps.length ? deps.join(', ') : '—'}
                    </td>
                    <td style={td()}>
                      <button
                        onClick={() => handleToggleTool(step.key)}
                        disabled={toggling}
                        style={{
                          background: 'none',
                          border: `1px solid ${on ? C.danger + '88' : C.accent + '88'}`,
                          borderRadius: '6px',
                          color: on ? C.danger : C.accent,
                          cursor: toggling ? 'default' : 'pointer',
                          fontSize: '0.78rem',
                          padding: '0.25rem 0.65rem',
                          opacity: toggling ? 0.5 : 1,
                          transition: 'opacity 0.15s',
                        }}
                      >
                        {toggling ? '…' : on ? 'Disable' : 'Enable'}
                      </button>
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan={4} style={{ ...td(), textAlign: 'center', color: C.muted, padding: '1.5rem' }}>
                  No tool steps configured.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* ── Recent Runs ── */}
      <div style={{ backgroundColor: C.card, border: `1px solid ${C.border}`, borderRadius: '10px', overflow: 'hidden' }}>
        <div style={{ padding: '0.75rem 1rem', borderBottom: `1px solid ${C.border}` }}>
          <h2 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600, color: '#e6edf3' }}>Recent Runs</h2>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
            <thead>
              <tr>
                {['Run ID', 'Status', 'Start', 'End', 'Duration', 'Step Results'].map(h => (
                  <th key={h} style={th}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {recent_runs.length > 0 ? (
                recent_runs.map((run, i) => {
                  const stepSummary = run.step_results
                    ? `${run.step_results.filter(s => s.status === 'completed').length}/${run.step_results.length} completed`
                    : '—';
                  return (
                    <tr
                      key={run.id || i}
                      style={{ borderBottom: i === recent_runs.length - 1 ? 'none' : `1px solid ${C.border}22` }}
                      onMouseEnter={e => e.currentTarget.style.backgroundColor = '#1c2128'}
                      onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
                    >
                      <td style={td({ fontFamily: 'monospace', fontSize: '0.78rem', color: C.muted })}>
                        {String(run.id || '—').slice(0, 8)}
                      </td>
                      <td style={td()}>
                        <Badge value={run.status} />
                      </td>
                      <td style={td({ color: C.muted, fontSize: '0.78rem', whiteSpace: 'nowrap' })}>
                        {fmtDate(run.started_at)}
                      </td>
                      <td style={td({ color: C.muted, fontSize: '0.78rem', whiteSpace: 'nowrap' })}>
                        {fmtDate(run.finished_at)}
                      </td>
                      <td style={td({ color: C.muted })}>
                        {fmtDuration(run.started_at, run.finished_at)}
                      </td>
                      <td style={td({ color: C.muted })}>
                        {stepSummary}
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={6} style={{ ...td(), textAlign: 'center', color: C.muted, padding: '1.5rem' }}>
                    No runs yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
