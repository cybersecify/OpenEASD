import React, { useState } from 'react';
import { useFetch } from '../hooks/useFetch.js';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { ConfirmButton } from '../components/ConfirmButton.jsx';
import { Notification } from '../components/Notification.jsx';
import { navigate } from '../App.jsx';
import { apiPost } from '../api/client.js';

// ── Shared tokens ────────────────────────────────────────────────────────────
const C = {
  bg:      '#0d1117',
  card:    '#161b22',
  border:  '#30363d',
  text:    '#c9d1d9',
  muted:   '#8b949e',
  accent:  '#30c074',
  danger:  '#f87171',
  critical:'#dc2626',
  high:    '#ea580c',
  medium:  '#ca8a04',
  low:     '#2563eb',
};

const font = "'Segoe UI', system-ui, -apple-system, sans-serif";

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function Btn({ children, onClick, variant = 'default', disabled, style: extra }) {
  const base = {
    background: 'none',
    border: `1px solid ${C.border}`,
    borderRadius: '6px',
    color: C.text,
    cursor: disabled ? 'not-allowed' : 'pointer',
    fontSize: '0.8rem',
    padding: '0.3rem 0.75rem',
    transition: 'border-color 0.15s ease, color 0.15s ease',
    opacity: disabled ? 0.5 : 1,
    ...extra,
  };
  const hoverColor = variant === 'primary' ? C.accent : variant === 'danger' ? C.danger : C.accent;

  return (
    <button
      onClick={disabled ? undefined : onClick}
      style={base}
      onMouseEnter={e => { if (!disabled) { e.currentTarget.style.borderColor = hoverColor; e.currentTarget.style.color = hoverColor; } }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.text; }}
    >
      {children}
    </button>
  );
}

function FindingsBadges({ summary }) {
  if (!summary) return <span style={{ color: C.muted }}>—</span>;
  const levels = [
    { key: 'critical', color: C.critical },
    { key: 'high',     color: C.high },
    { key: 'medium',   color: C.medium },
    { key: 'low',      color: C.low },
  ];
  const hasAny = levels.some(l => summary[l.key] > 0);
  if (!hasAny) return <span style={{ color: C.muted, fontSize: '0.8rem' }}>none</span>;

  return (
    <span style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
      {levels.map(({ key, color }) =>
        summary[key] > 0 ? (
          <span key={key} style={{
            display: 'inline-block',
            padding: '1px 7px',
            borderRadius: '9999px',
            fontSize: '0.72rem',
            fontWeight: 600,
            background: color + '22',
            color: color,
            border: `1px solid ${color}44`,
          }}>
            {summary[key]} {key}
          </span>
        ) : null
      )}
    </span>
  );
}

// Styled ConfirmButton wrapper that matches the table button style
function DeleteButton({ onConfirm }) {
  const [confirming, setConfirming] = useState(false);

  if (confirming) {
    return (
      <span style={{ display: 'inline-flex', gap: '4px', alignItems: 'center' }}>
        <button
          onClick={() => { setConfirming(false); onConfirm(); }}
          style={{
            background: 'none', border: `1px solid ${C.danger}`, borderRadius: '6px',
            color: C.danger, cursor: 'pointer', fontSize: '0.8rem', padding: '0.3rem 0.6rem',
          }}
        >
          Confirm
        </button>
        <button
          onClick={() => setConfirming(false)}
          style={{
            background: 'none', border: `1px solid ${C.border}`, borderRadius: '6px',
            color: C.muted, cursor: 'pointer', fontSize: '0.8rem', padding: '0.3rem 0.6rem',
          }}
        >
          Cancel
        </button>
      </span>
    );
  }

  return (
    <button
      onClick={() => setConfirming(true)}
      style={{
        background: 'none', border: `1px solid ${C.border}`, borderRadius: '6px',
        color: C.text, cursor: 'pointer', fontSize: '0.8rem', padding: '0.3rem 0.75rem',
        transition: 'border-color 0.15s ease, color 0.15s ease',
      }}
      onMouseEnter={e => { e.currentTarget.style.borderColor = C.danger; e.currentTarget.style.color = C.danger; }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.text; }}
    >
      Delete
    </button>
  );
}

export default function DomainsPage() {
  const { data: domains, loading, error, refetch } = useFetch('/domains/');
  const [newName, setNewName] = useState('');
  const [adding, setAdding] = useState(false);
  const [notification, setNotification] = useState(null); // {message, type}
  const [busyIds, setBusyIds] = useState(new Set());

  function notify(message, type = 'success') {
    setNotification({ message, type, key: Date.now() });
  }

  async function handleAdd(e) {
    e.preventDefault();
    const name = newName.trim();
    if (!name) return;
    setAdding(true);
    try {
      await apiPost('/domains/', { name });
      setNewName('');
      notify(`Domain "${name}" added.`);
      refetch();
    } catch (err) {
      notify(err.message || 'Failed to add domain.', 'error');
    } finally {
      setAdding(false);
    }
  }

  async function handleToggle(domain) {
    setBusyIds(s => new Set([...s, domain.id]));
    try {
      await apiPost(`/domains/${domain.id}/toggle/`);
      refetch();
    } catch (err) {
      notify(err.message || 'Toggle failed.', 'error');
    } finally {
      setBusyIds(s => { const ns = new Set(s); ns.delete(domain.id); return ns; });
    }
  }

  async function handleDelete(domain) {
    setBusyIds(s => new Set([...s, domain.id]));
    try {
      await apiPost(`/domains/${domain.id}/delete/`);
      notify(`Domain "${domain.name}" deleted.`);
      refetch();
    } catch (err) {
      notify(err.message || 'Delete failed.', 'error');
    } finally {
      setBusyIds(s => { const ns = new Set(s); ns.delete(domain.id); return ns; });
    }
  }

  const thStyle = {
    padding: '0.75rem 1rem',
    textAlign: 'left',
    color: C.muted,
    fontWeight: 600,
    fontSize: '0.78rem',
    letterSpacing: '0.04em',
    textTransform: 'uppercase',
  };
  const tdStyle = { padding: '0.75rem 1rem' };

  return (
    <div style={{ fontFamily: font, backgroundColor: C.bg, minHeight: '100vh', color: C.text, padding: '2rem', boxSizing: 'border-box' }}>

      {notification && (
        <Notification key={notification.key} message={notification.message} type={notification.type} />
      )}

      {/* Page header */}
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ margin: 0, fontSize: '1.4rem', fontWeight: 700, color: '#e6edf3' }}>Domains</h1>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.85rem', color: C.muted }}>
          Manage domains in your attack surface
        </p>
      </div>

      {/* ── Add domain form ── */}
      <div style={{
        backgroundColor: C.card,
        border: `1px solid ${C.border}`,
        borderRadius: '10px',
        padding: '1rem 1.5rem',
        marginBottom: '1.5rem',
      }}>
        <form onSubmit={handleAdd} style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{ color: C.muted, fontSize: '0.85rem', fontWeight: 600, minWidth: '80px' }}>Add Domain</span>
          <input
            type="text"
            value={newName}
            onChange={e => setNewName(e.target.value)}
            placeholder="example.com"
            disabled={adding}
            style={{
              flex: '1',
              minWidth: '200px',
              background: C.bg,
              border: `1px solid ${C.border}`,
              borderRadius: '6px',
              color: C.text,
              fontSize: '0.875rem',
              padding: '0.4rem 0.75rem',
              outline: 'none',
            }}
            onFocus={e => e.currentTarget.style.borderColor = C.accent}
            onBlur={e => e.currentTarget.style.borderColor = C.border}
          />
          <button
            type="submit"
            disabled={adding || !newName.trim()}
            style={{
              background: adding || !newName.trim() ? C.border : C.accent,
              border: 'none',
              borderRadius: '6px',
              color: '#0d1117',
              cursor: adding || !newName.trim() ? 'not-allowed' : 'pointer',
              fontSize: '0.875rem',
              fontWeight: 600,
              padding: '0.4rem 1.25rem',
              transition: 'background 0.15s ease',
              opacity: adding || !newName.trim() ? 0.6 : 1,
            }}
          >
            {adding ? 'Adding…' : 'Add'}
          </button>
        </form>
      </div>

      {/* ── Domains table ── */}
      <div style={{
        backgroundColor: C.card,
        border: `1px solid ${C.border}`,
        borderRadius: '10px',
        overflow: 'hidden',
      }}>
        {loading ? (
          <div style={{ padding: '2rem', display: 'flex', justifyContent: 'center' }}><Spinner /></div>
        ) : error ? (
          <div style={{ padding: '2rem', color: C.danger }}>Error: {error}</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {['Name', 'Status', 'Last Scan', 'Findings', 'Actions'].map(h => (
                  <th key={h} style={thStyle}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {domains && domains.length > 0 ? (
                domains.map((domain, i) => {
                  const busy = busyIds.has(domain.id);
                  const isLast = i === domains.length - 1;
                  return (
                    <tr
                      key={domain.id}
                      style={{
                        borderBottom: isLast ? 'none' : `1px solid ${C.border}`,
                        transition: 'background-color 0.1s ease',
                      }}
                      onMouseEnter={e => e.currentTarget.style.backgroundColor = '#1c2128'}
                      onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
                    >
                      {/* Name */}
                      <td style={{ ...tdStyle, color: '#e6edf3', fontWeight: 500 }}>
                        <span>{domain.name}</span>
                        {domain.is_primary && (
                          <span style={{ marginLeft: '0.5rem', fontSize: '0.7rem', color: C.accent, fontWeight: 600 }}>
                            PRIMARY
                          </span>
                        )}
                      </td>

                      {/* Status */}
                      <td style={tdStyle}>
                        <Badge value={domain.is_active ? 'completed' : 'cancelled'} label={domain.is_active ? 'active' : 'inactive'} />
                      </td>

                      {/* Last Scan */}
                      <td style={{ ...tdStyle, color: C.muted }}>
                        {domain.last_scan ? (
                          <span>
                            <Badge value={domain.last_scan.status} />
                            <span style={{ marginLeft: '0.5rem', fontSize: '0.8rem' }}>
                              {fmtDate(domain.last_scan.start_time)}
                            </span>
                          </span>
                        ) : (
                          <span style={{ color: C.muted }}>Never</span>
                        )}
                      </td>

                      {/* Findings */}
                      <td style={tdStyle}>
                        <FindingsBadges summary={domain.findings_summary} />
                      </td>

                      {/* Actions */}
                      <td style={tdStyle}>
                        <span style={{ display: 'inline-flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
                          <button
                            onClick={() => navigate(`/scans/start?domain=${encodeURIComponent(domain.name)}`)}
                            disabled={busy}
                            style={{
                              background: 'none',
                              border: `1px solid ${C.border}`,
                              borderRadius: '6px',
                              color: C.text,
                              cursor: busy ? 'not-allowed' : 'pointer',
                              fontSize: '0.8rem',
                              padding: '0.3rem 0.75rem',
                              transition: 'border-color 0.15s ease, color 0.15s ease',
                              opacity: busy ? 0.5 : 1,
                            }}
                            onMouseEnter={e => { if (!busy) { e.currentTarget.style.borderColor = C.accent; e.currentTarget.style.color = C.accent; } }}
                            onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.text; }}
                          >
                            Scan
                          </button>
                          {domain.last_scan?.uuid && (
                            <button
                              onClick={() => navigate(`/scans/${domain.last_scan.uuid}`)}
                              style={{
                                background: 'none',
                                border: `1px solid ${C.border}`,
                                borderRadius: '6px',
                                color: C.text,
                                cursor: 'pointer',
                                fontSize: '0.8rem',
                                padding: '0.3rem 0.75rem',
                                transition: 'border-color 0.15s ease, color 0.15s ease',
                              }}
                              onMouseEnter={e => { e.currentTarget.style.borderColor = C.accent; e.currentTarget.style.color = C.accent; }}
                              onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.text; }}
                            >
                              View
                            </button>
                          )}
                          <button
                            onClick={() => !busy && handleToggle(domain)}
                            disabled={busy}
                            style={{
                              background: 'none',
                              border: `1px solid ${C.border}`,
                              borderRadius: '6px',
                              color: C.text,
                              cursor: busy ? 'not-allowed' : 'pointer',
                              fontSize: '0.8rem',
                              padding: '0.3rem 0.75rem',
                              transition: 'border-color 0.15s ease, color 0.15s ease',
                              opacity: busy ? 0.5 : 1,
                            }}
                            onMouseEnter={e => { if (!busy) { e.currentTarget.style.borderColor = C.accent; e.currentTarget.style.color = C.accent; } }}
                            onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.text; }}
                          >
                            {domain.is_active ? 'Deactivate' : 'Activate'}
                          </button>
                          <DeleteButton onConfirm={() => handleDelete(domain)} />
                        </span>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={5} style={{ padding: '2.5rem', textAlign: 'center', color: C.muted }}>
                    No domains yet. Add one above.
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
