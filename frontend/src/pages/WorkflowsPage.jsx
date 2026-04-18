import React, { useState, useCallback } from 'react';
import { Spinner } from '../components/Spinner.jsx';
import { Notification } from '../components/Notification.jsx';
import { navigate } from '../App.jsx';
import { apiFetch, apiPost } from '../api/client.js';
import { useFetch } from '../hooks/useFetch.js';

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

function DeleteButton({ onConfirm, disabled }) {
  const [confirming, setConfirming] = useState(false);
  if (confirming) {
    return (
      <span style={{ display: 'inline-flex', gap: '4px', alignItems: 'center' }}>
        <button
          onClick={() => { setConfirming(false); onConfirm(); }}
          style={{ background: 'none', border: `1px solid ${C.danger}`, borderRadius: '6px', color: C.danger, cursor: 'pointer', fontSize: '0.8rem', padding: '0.3rem 0.6rem' }}
        >
          Confirm
        </button>
        <button
          onClick={() => setConfirming(false)}
          style={{ background: 'none', border: `1px solid ${C.border}`, borderRadius: '6px', color: C.muted, cursor: 'pointer', fontSize: '0.8rem', padding: '0.3rem 0.6rem' }}
        >
          Cancel
        </button>
      </span>
    );
  }
  return (
    <button
      disabled={disabled}
      onClick={() => setConfirming(true)}
      style={{ background: 'none', border: `1px solid ${C.border}`, borderRadius: '6px', color: C.text, cursor: disabled ? 'default' : 'pointer', fontSize: '0.8rem', padding: '0.3rem 0.75rem', opacity: disabled ? 0.5 : 1, transition: 'border-color 0.15s, color 0.15s' }}
      onMouseEnter={e => { if (!disabled) { e.currentTarget.style.borderColor = C.danger; e.currentTarget.style.color = C.danger; } }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.text; }}
    >
      Delete
    </button>
  );
}

// Inline "Create Workflow" form
function CreateWorkflowForm({ onCreated }) {
  const [name, setName]           = useState('');
  const [description, setDesc]    = useState('');
  const [isDefault, setIsDefault] = useState(false);
  const [selectedTools, setSel]   = useState([]);
  const [saving, setSaving]       = useState(false);
  const [err, setErr]             = useState(null);

  const { data: toolsData } = useFetch('/workflows/tools/');
  const allTools = toolsData?.tools || [];

  function toggleTool(key) {
    setSel(prev => prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]);
  }

  async function handleCreate(e) {
    e.preventDefault();
    if (!name.trim()) { setErr('Name is required.'); return; }
    setSaving(true);
    setErr(null);
    try {
      const res = await apiPost('/workflows/create/', {
        name: name.trim(),
        description: description.trim(),
        is_default: isDefault,
        tools: selectedTools,
      });
      onCreated(res.data);
      setName(''); setDesc(''); setIsDefault(false); setSel([]);
    } catch (e) {
      setErr(e.message);
    } finally {
      setSaving(false);
    }
  }

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
    <div style={{ backgroundColor: C.card, border: `1px solid ${C.border}`, borderRadius: '10px', padding: '1.25rem', marginBottom: '1.5rem' }}>
      <h2 style={{ margin: '0 0 1rem', fontSize: '1rem', fontWeight: 600, color: '#e6edf3' }}>Create Workflow</h2>
      <form onSubmit={handleCreate}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '0.75rem' }}>
          <div>
            <label style={{ fontSize: '0.8rem', color: C.muted, display: 'block', marginBottom: '0.3rem' }}>Name *</label>
            <input value={name} onChange={e => setName(e.target.value)} placeholder="Workflow name" style={inputStyle}
              onFocus={e => e.currentTarget.style.borderColor = C.accent}
              onBlur={e => e.currentTarget.style.borderColor = C.border}
            />
          </div>
          <div>
            <label style={{ fontSize: '0.8rem', color: C.muted, display: 'block', marginBottom: '0.3rem' }}>Description</label>
            <input value={description} onChange={e => setDesc(e.target.value)} placeholder="Optional description" style={inputStyle}
              onFocus={e => e.currentTarget.style.borderColor = C.accent}
              onBlur={e => e.currentTarget.style.borderColor = C.border}
            />
          </div>
        </div>

        <div style={{ marginBottom: '0.75rem' }}>
          <label style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85rem', color: C.text, cursor: 'pointer' }}>
            <input type="checkbox" checked={isDefault} onChange={e => setIsDefault(e.target.checked)} style={{ accentColor: C.accent }} />
            Set as default workflow
          </label>
        </div>

        {allTools.length > 0 && (
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ fontSize: '0.8rem', color: C.muted, display: 'block', marginBottom: '0.5rem' }}>Tools</label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
              {allTools.map(tool => (
                <label key={tool.key} style={{
                  display: 'inline-flex', alignItems: 'center', gap: '0.35rem',
                  background: selectedTools.includes(tool.key) ? C.accent + '22' : C.bg,
                  border: `1px solid ${selectedTools.includes(tool.key) ? C.accent + '66' : C.border}`,
                  borderRadius: '6px',
                  padding: '0.3rem 0.65rem',
                  fontSize: '0.8rem',
                  color: selectedTools.includes(tool.key) ? C.accent : C.text,
                  cursor: 'pointer',
                  transition: 'all 0.15s',
                }}>
                  <input type="checkbox" checked={selectedTools.includes(tool.key)} onChange={() => toggleTool(tool.key)} style={{ accentColor: C.accent }} />
                  {tool.label || tool.key}
                </label>
              ))}
            </div>
          </div>
        )}

        {err && <div style={{ color: C.danger, fontSize: '0.82rem', marginBottom: '0.75rem' }}>{err}</div>}

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
          {saving ? 'Creating…' : 'Create Workflow'}
        </button>
      </form>
    </div>
  );
}

export default function WorkflowsPage() {
  const { data: rawData, loading, error, refetch } = useFetch('/workflows/');
  const [notification, setNotification] = useState(null);
  const [busyIds, setBusyIds] = useState(new Set());

  const workflows = rawData || [];

  function notify(message, type = 'success') {
    setNotification({ message, type, key: Date.now() });
  }

  async function handleDelete(id, name) {
    setBusyIds(s => new Set([...s, id]));
    try {
      await apiPost(`/workflows/${id}/delete/`);
      notify(`Workflow "${name}" deleted.`);
      refetch();
    } catch (e) {
      notify(e.message || 'Delete failed.', 'error');
    } finally {
      setBusyIds(s => { const ns = new Set(s); ns.delete(id); return ns; });
    }
  }

  function handleCreated() {
    notify('Workflow created.');
    refetch();
  }

  const thStyle = {
    padding: '0.65rem 1rem',
    textAlign: 'left',
    color: C.muted,
    fontWeight: 600,
    fontSize: '0.75rem',
    letterSpacing: '0.04em',
    textTransform: 'uppercase',
    whiteSpace: 'nowrap',
  };
  const tdStyle = { padding: '0.65rem 1rem', verticalAlign: 'middle' };

  return (
    <div style={{ fontFamily: font, backgroundColor: C.bg, minHeight: '100vh', color: C.text, padding: '2rem', boxSizing: 'border-box' }}>

      {notification && (
        <Notification key={notification.key} message={notification.message} type={notification.type} />
      )}

      {/* Header */}
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ margin: 0, fontSize: '1.4rem', fontWeight: 700, color: '#e6edf3' }}>Workflows</h1>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.85rem', color: C.muted }}>
          Manage scan workflows and tool configurations
        </p>
      </div>

      {/* Create form */}
      <CreateWorkflowForm onCreated={handleCreated} />

      {/* Workflows table */}
      <div style={{ backgroundColor: C.card, border: `1px solid ${C.border}`, borderRadius: '10px', overflow: 'hidden' }}>
        {loading ? (
          <div style={{ padding: '2rem', display: 'flex', justifyContent: 'center' }}><Spinner /></div>
        ) : error ? (
          <div style={{ padding: '2rem', color: C.danger }}>Error: {error}</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {['Name', 'Default?', 'Tools', 'Description', 'Actions'].map(h => (
                  <th key={h} style={thStyle}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {workflows.length > 0 ? (
                workflows.map((wf, i) => {
                  const busy = busyIds.has(wf.id);
                  return (
                    <tr
                      key={wf.id}
                      style={{
                        borderBottom: i === workflows.length - 1 ? 'none' : `1px solid ${C.border}`,
                        transition: 'background-color 0.1s ease',
                        opacity: busy ? 0.6 : 1,
                      }}
                      onMouseEnter={e => e.currentTarget.style.backgroundColor = '#1c2128'}
                      onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
                    >
                      <td style={{ ...tdStyle, color: '#e6edf3', fontWeight: 500 }}>{wf.name}</td>
                      <td style={tdStyle}>
                        {wf.is_default
                          ? <span style={{ color: C.accent, fontSize: '0.8rem', fontWeight: 600 }}>Default</span>
                          : <span style={{ color: C.muted, fontSize: '0.8rem' }}>—</span>}
                      </td>
                      <td style={{ ...tdStyle, color: C.muted }}>
                        {wf.steps ? wf.steps.filter(s => s.enabled !== false).length : '—'}
                      </td>
                      <td style={{ ...tdStyle, color: C.muted, maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {wf.description || '—'}
                      </td>
                      <td style={tdStyle}>
                        <span style={{ display: 'inline-flex', gap: '6px', alignItems: 'center' }}>
                          <button
                            onClick={() => navigate(`/workflows/${wf.id}`)}
                            style={{ background: 'none', border: `1px solid ${C.border}`, borderRadius: '6px', color: C.text, cursor: 'pointer', fontSize: '0.8rem', padding: '0.3rem 0.75rem', transition: 'border-color 0.15s, color 0.15s' }}
                            onMouseEnter={e => { e.currentTarget.style.borderColor = C.accent; e.currentTarget.style.color = C.accent; }}
                            onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.text; }}
                          >
                            View
                          </button>
                          <DeleteButton
                            disabled={busy}
                            onConfirm={() => handleDelete(wf.id, wf.name)}
                          />
                        </span>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={5} style={{ padding: '2.5rem', textAlign: 'center', color: C.muted }}>
                    No workflows yet. Create one above.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
