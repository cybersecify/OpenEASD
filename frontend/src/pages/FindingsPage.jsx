import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Pagination } from '../components/Pagination.jsx';
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
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

const SEVERITY_OPTIONS = ['', 'critical', 'high', 'medium', 'low', 'info'];
const STATUS_OPTIONS   = ['', 'open', 'in_progress', 'resolved', 'accepted', 'false_positive'];

const SEV_COLORS = {
  critical: '#dc2626',
  high:     '#ea580c',
  medium:   '#ca8a04',
  low:      '#2563eb',
  info:     '#6b7280',
};

function KpiCard({ label, value, color }) {
  return (
    <div style={{
      flex: '1 1 130px',
      background: (color || '#6b7280') + '11',
      border: `1px solid ${(color || '#6b7280')}44`,
      borderRadius: '8px',
      padding: '1rem',
      textAlign: 'center',
    }}>
      <div style={{ fontSize: '1.75rem', fontWeight: 700, color: color || C.muted }}>{value ?? 0}</div>
      <div style={{ fontSize: '0.75rem', color: color || C.muted, marginTop: '2px', textTransform: 'capitalize' }}>{label}</div>
    </div>
  );
}

// Inline row editor for status update
function StatusEditor({ finding, onSaved }) {
  const [status, setStatus]   = useState(finding.status || 'open');
  const [saving, setSaving]   = useState(false);
  const [err, setErr]         = useState(null);

  async function handleSave() {
    setSaving(true);
    setErr(null);
    try {
      const res = await apiPost(`/scans/findings/${finding.id}/status/`, { status });
      onSaved(res.data || { ...finding, status });
    } catch (e) {
      setErr(e.message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <span style={{ display: 'inline-flex', gap: '4px', alignItems: 'center' }}>
      <select
        value={status}
        onChange={e => setStatus(e.target.value)}
        disabled={saving}
        style={{
          background: C.bg,
          border: `1px solid ${C.border}`,
          borderRadius: '5px',
          color: C.text,
          fontSize: '0.78rem',
          padding: '0.2rem 0.45rem',
          outline: 'none',
          cursor: 'pointer',
        }}
      >
        {STATUS_OPTIONS.filter(Boolean).map(s => (
          <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>
        ))}
      </select>
      <button
        onClick={handleSave}
        disabled={saving || status === finding.status}
        style={{
          background: 'none',
          border: `1px solid ${C.border}`,
          borderRadius: '5px',
          color: saving ? C.muted : C.accent,
          cursor: saving || status === finding.status ? 'default' : 'pointer',
          fontSize: '0.78rem',
          padding: '0.2rem 0.55rem',
          opacity: (saving || status === finding.status) ? 0.5 : 1,
          transition: 'opacity 0.1s',
        }}
      >
        {saving ? '…' : 'Save'}
      </button>
      {err && <span style={{ color: C.danger, fontSize: '0.75rem' }}>{err}</span>}
    </span>
  );
}

export default function FindingsPage() {
  const params        = new URLSearchParams(window.location.search);
  const currentSev    = params.get('severity') || '';
  const currentDomain = params.get('domain')   || '';
  const currentStatus = params.get('status')   || '';
  const currentSource = params.get('source')   || '';
  const currentPage   = parseInt(params.get('page') || '1', 10);

  const [domainInput, setDomainInput] = useState(currentDomain);
  const [sourceInput, setSourceInput] = useState(currentSource);
  const [notification, setNotification] = useState(null);

  const [findings, setFindings]     = useState(null);
  const [counts, setCounts]         = useState(null);
  const [pagination, setPagination] = useState(null);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState(null);

  // Build API qs from URL params
  const apiQs = useMemo(() => {
    const p = new URLSearchParams();
    if (currentSev)    p.set('severity', currentSev);
    if (currentDomain) p.set('domain', currentDomain);
    if (currentStatus) p.set('status', currentStatus);
    if (currentSource) p.set('source', currentSource);
    if (currentPage > 1) p.set('page', String(currentPage));
    const qs = p.toString();
    return qs ? `?${qs}` : '';
  }, [currentSev, currentDomain, currentStatus, currentSource, currentPage]);

  const fetchFindings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch(`/scans/findings/${apiQs}`, { method: 'GET' });
      setFindings(res.data.findings);
      setCounts(res.data.counts);
      setPagination(res.pagination || null);
    } catch (e) {
      setError(e.message);
      if (e.status === 401) window.location.href = '/login';
    } finally {
      setLoading(false);
    }
  }, [apiQs]);

  useEffect(() => { fetchFindings(); }, [fetchFindings]);

  // Debounce domain input → navigate
  useEffect(() => {
    const timer = setTimeout(() => {
      if (domainInput === currentDomain) return;
      pushFilters({ domain: domainInput.trim() });
    }, 400);
    return () => clearTimeout(timer);
  }, [domainInput]);

  // Debounce source input → navigate
  useEffect(() => {
    const timer = setTimeout(() => {
      if (sourceInput === currentSource) return;
      pushFilters({ source: sourceInput.trim() });
    }, 400);
    return () => clearTimeout(timer);
  }, [sourceInput]);

  // Sync inputs when URL changes (back/forward)
  useEffect(() => { setDomainInput(currentDomain); }, [currentDomain]);
  useEffect(() => { setSourceInput(currentSource); }, [currentSource]);

  function pushFilters(overrides = {}) {
    const next = {
      ...(currentSev    ? { severity: currentSev }    : {}),
      ...(currentDomain ? { domain: currentDomain }   : {}),
      ...(currentStatus ? { status: currentStatus }   : {}),
      ...(currentSource ? { source: currentSource }   : {}),
      ...overrides,
    };
    // remove empties
    Object.keys(next).forEach(k => { if (!next[k]) delete next[k]; });
    const qs = new URLSearchParams(next).toString();
    navigate(qs ? `/findings?${qs}` : '/findings');
  }

  function handleFindingUpdated(updated) {
    setFindings(prev => prev.map(f => f.id === updated.id ? { ...f, ...updated } : f));
    setNotification({ message: 'Status updated.', type: 'success', key: Date.now() });
  }

  const hasFilters = currentSev || currentDomain || currentStatus || currentSource;

  const thStyle = {
    padding: '0.65rem 0.9rem',
    textAlign: 'left',
    color: C.muted,
    fontWeight: 600,
    fontSize: '0.75rem',
    letterSpacing: '0.04em',
    textTransform: 'uppercase',
    whiteSpace: 'nowrap',
  };
  const tdStyle = { padding: '0.65rem 0.9rem', verticalAlign: 'middle' };

  return (
    <div style={{ fontFamily: font, backgroundColor: C.bg, minHeight: '100vh', color: C.text, padding: '2rem', boxSizing: 'border-box' }}>

      {notification && (
        <Notification key={notification.key} message={notification.message} type={notification.type} />
      )}

      {/* Header */}
      <div style={{ marginBottom: '1.5rem' }}>
        <h1 style={{ margin: 0, fontSize: '1.4rem', fontWeight: 700, color: '#e6edf3' }}>Findings</h1>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.85rem', color: C.muted }}>
          All findings across scans
        </p>
      </div>

      {/* KPI cards */}
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '1.5rem' }}>
        <KpiCard label="Open Critical" value={counts?.open_critical} color={SEV_COLORS.critical} />
        <KpiCard label="Open High"     value={counts?.open_high}     color={SEV_COLORS.high} />
        <KpiCard label="Open Medium"   value={counts?.open_medium}   color={SEV_COLORS.medium} />
        <KpiCard label="Open Low"      value={counts?.open_low}      color={SEV_COLORS.low} />
      </div>

      {/* Filter bar */}
      <div style={{
        backgroundColor: C.card,
        border: `1px solid ${C.border}`,
        borderRadius: '10px',
        padding: '0.75rem 1.25rem',
        marginBottom: '1.25rem',
        display: 'flex',
        gap: '0.75rem',
        alignItems: 'center',
        flexWrap: 'wrap',
      }}>
        <span style={{ color: C.muted, fontSize: '0.85rem', fontWeight: 600 }}>Filter</span>

        {/* Severity */}
        <select
          value={currentSev}
          onChange={e => pushFilters({ severity: e.target.value })}
          style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: '6px', color: currentSev ? C.text : C.muted, fontSize: '0.875rem', padding: '0.35rem 0.75rem', outline: 'none', cursor: 'pointer' }}
          onFocus={e => e.currentTarget.style.borderColor = C.accent}
          onBlur={e => e.currentTarget.style.borderColor = C.border}
        >
          <option value="">All severities</option>
          {SEVERITY_OPTIONS.filter(Boolean).map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>

        {/* Status */}
        <select
          value={currentStatus}
          onChange={e => pushFilters({ status: e.target.value })}
          style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: '6px', color: currentStatus ? C.text : C.muted, fontSize: '0.875rem', padding: '0.35rem 0.75rem', outline: 'none', cursor: 'pointer' }}
          onFocus={e => e.currentTarget.style.borderColor = C.accent}
          onBlur={e => e.currentTarget.style.borderColor = C.border}
        >
          <option value="">All statuses</option>
          {STATUS_OPTIONS.filter(Boolean).map(s => (
            <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>
          ))}
        </select>

        {/* Domain */}
        <input
          type="text"
          value={domainInput}
          onChange={e => setDomainInput(e.target.value)}
          placeholder="Domain…"
          style={{ flex: '1', minWidth: '140px', maxWidth: '240px', background: C.bg, border: `1px solid ${C.border}`, borderRadius: '6px', color: C.text, fontSize: '0.875rem', padding: '0.35rem 0.75rem', outline: 'none' }}
          onFocus={e => e.currentTarget.style.borderColor = C.accent}
          onBlur={e => e.currentTarget.style.borderColor = C.border}
        />

        {/* Source */}
        <input
          type="text"
          value={sourceInput}
          onChange={e => setSourceInput(e.target.value)}
          placeholder="Source…"
          style={{ flex: '1', minWidth: '120px', maxWidth: '200px', background: C.bg, border: `1px solid ${C.border}`, borderRadius: '6px', color: C.text, fontSize: '0.875rem', padding: '0.35rem 0.75rem', outline: 'none' }}
          onFocus={e => e.currentTarget.style.borderColor = C.accent}
          onBlur={e => e.currentTarget.style.borderColor = C.border}
        />

        {hasFilters && (
          <button
            onClick={() => { setDomainInput(''); setSourceInput(''); navigate('/findings'); }}
            style={{ background: 'none', border: `1px solid ${C.border}`, borderRadius: '6px', color: C.muted, cursor: 'pointer', fontSize: '0.8rem', padding: '0.3rem 0.75rem' }}
          >
            Clear
          </button>
        )}
      </div>

      {/* Table */}
      <div style={{ backgroundColor: C.card, border: `1px solid ${C.border}`, borderRadius: '10px', overflow: 'hidden', marginBottom: '1.5rem' }}>
        {loading ? (
          <div style={{ padding: '2rem', display: 'flex', justifyContent: 'center' }}><Spinner /></div>
        ) : error ? (
          <div style={{ padding: '2rem', color: C.danger }}>Error: {error}</div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                  {['Severity', 'Title', 'Source', 'Check Type', 'Target', 'Status', 'Discovered', 'Actions'].map(h => (
                    <th key={h} style={thStyle}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {findings && findings.length > 0 ? (
                  findings.map((f, i) => (
                    <tr
                      key={f.id}
                      style={{
                        borderBottom: i === findings.length - 1 ? 'none' : `1px solid ${C.border}`,
                        transition: 'background-color 0.1s ease',
                      }}
                      onMouseEnter={e => e.currentTarget.style.backgroundColor = '#1c2128'}
                      onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
                    >
                      <td style={tdStyle}>
                        <Badge value={f.severity} />
                      </td>
                      <td style={{ ...tdStyle, color: '#e6edf3', fontWeight: 500, maxWidth: '280px' }}>
                        <div style={{ whiteSpace: 'normal', wordBreak: 'break-word' }}>{f.title}</div>
                        {f.description && (
                          <div style={{ fontSize: '0.75rem', color: C.muted, marginTop: '2px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '260px' }}>
                            {f.description}
                          </div>
                        )}
                      </td>
                      <td style={{ ...tdStyle, color: C.muted }}>{f.source || '—'}</td>
                      <td style={{ ...tdStyle, color: C.muted, fontFamily: 'monospace', fontSize: '0.78rem' }}>{f.check_type || '—'}</td>
                      <td style={{ ...tdStyle, color: C.muted, fontFamily: 'monospace', fontSize: '0.78rem', maxWidth: '180px', wordBreak: 'break-all' }}>{f.target || '—'}</td>
                      <td style={tdStyle}>
                        <Badge value={f.status || 'open'} />
                      </td>
                      <td style={{ ...tdStyle, color: C.muted, fontSize: '0.78rem', whiteSpace: 'nowrap' }}>
                        {fmtDate(f.discovered_at)}
                      </td>
                      <td style={tdStyle}>
                        <StatusEditor finding={f} onSaved={handleFindingUpdated} />
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={8} style={{ padding: '2.5rem', textAlign: 'center', color: C.muted }}>
                      {hasFilters ? 'No findings match these filters.' : 'No findings yet.'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {!loading && (
        <Pagination
          pagination={pagination}
          basePath="/findings"
          params={{
            ...(currentSev    ? { severity: currentSev }    : {}),
            ...(currentDomain ? { domain: currentDomain }   : {}),
            ...(currentStatus ? { status: currentStatus }   : {}),
            ...(currentSource ? { source: currentSource }   : {}),
          }}
        />
      )}
    </div>
  );
}
