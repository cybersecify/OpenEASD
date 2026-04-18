import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Badge } from '../components/Badge.jsx';
import { Spinner } from '../components/Spinner.jsx';
import { Pagination } from '../components/Pagination.jsx';
import { Notification } from '../components/Notification.jsx';
import { navigate } from '../App.jsx';
import { apiPost, apiFetch } from '../api/client.js';
import { useFetch } from '../hooks/useFetch.js';

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

function fmtDuration(start, end) {
  if (!start || !end) return null;
  const ms = new Date(end) - new Date(start);
  if (ms < 0) return null;
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

const STATUS_OPTIONS = ['', 'pending', 'running', 'completed', 'failed', 'cancelled'];

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

function FindingsSummary({ total }) {
  if (total == null) return <span style={{ color: C.muted }}>—</span>;
  return <span style={{ color: total > 0 ? C.accent : C.muted }}>{total}</span>;
}

export default function ScansPage() {
  // Parse filters from current URL query string
  const params = new URLSearchParams(window.location.search);
  const currentDomain = params.get('domain') || '';
  const currentStatus = params.get('status') || '';
  const currentPage   = parseInt(params.get('page') || '1', 10);

  // Local input state (debounced for domain)
  const [domainInput, setDomainInput] = useState(currentDomain);
  const [notification, setNotification] = useState(null);
  const [busyUuids, setBusyUuids] = useState(new Set());

  // Build API query string from URL params
  const apiQs = useMemo(() => {
    const p = new URLSearchParams();
    if (currentDomain) p.set('domain', currentDomain);
    if (currentStatus) p.set('status', currentStatus);
    if (currentPage > 1) p.set('page', String(currentPage));
    const qs = p.toString();
    return qs ? `?${qs}` : '';
  }, [currentDomain, currentStatus, currentPage]);

  // Manual fetch to capture both data + pagination from the API response
  const [scansData, setScansData] = useState(null);
  const [pagination, setPagination] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchScans = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch(`/scans/${apiQs}`, { method: 'GET' });
      setScansData(res.data);
      setPagination(res.pagination || null);
    } catch (e) {
      setError(e.message);
      if (e.status === 401) window.location.href = '/login';
    } finally {
      setLoading(false);
    }
  }, [apiQs]);

  useEffect(() => { fetchScans(); }, [fetchScans]);

  const refetch = fetchScans;

  const { data: scheduledData, loading: schedLoading } = useFetch('/scheduled/');

  // Debounce domain input → navigate
  useEffect(() => {
    const timer = setTimeout(() => {
      if (domainInput === currentDomain) return;
      const p = new URLSearchParams();
      if (domainInput.trim()) p.set('domain', domainInput.trim());
      if (currentStatus) p.set('status', currentStatus);
      const qs = p.toString();
      navigate(qs ? `/scans?${qs}` : '/scans');
    }, 400);
    return () => clearTimeout(timer);
  }, [domainInput]);

  // Sync input if URL domain changes (e.g. back/forward)
  useEffect(() => {
    setDomainInput(currentDomain);
  }, [currentDomain]);

  function handleStatusChange(e) {
    const val = e.target.value;
    const p = new URLSearchParams();
    if (currentDomain) p.set('domain', currentDomain);
    if (val) p.set('status', val);
    const qs = p.toString();
    navigate(qs ? `/scans?${qs}` : '/scans');
  }

  function notify(message, type = 'success') {
    setNotification({ message, type, key: Date.now() });
  }

  async function handleDelete(uuid) {
    setBusyUuids(s => new Set([...s, uuid]));
    try {
      await apiPost(`/scans/${uuid}/delete/`);
      notify(`Scan ${uuid.slice(0, 8)}… deleted.`);
      refetch();
    } catch (err) {
      notify(err.message || 'Delete failed.', 'error');
    } finally {
      setBusyUuids(s => { const ns = new Set(s); ns.delete(uuid); return ns; });
    }
  }

  async function handleCancelJob(jobId) {
    try {
      await apiPost(`/scheduled/${jobId}/cancel/`);
      notify(`Scheduled job cancelled.`);
    } catch (err) {
      notify(err.message || 'Cancel failed.', 'error');
    }
  }

  // Compute status counts from current page of results
  const statusCounts = useMemo(() => {
    if (!scansData) return {};
    const counts = {};
    scansData.forEach(s => {
      counts[s.status] = (counts[s.status] || 0) + 1;
    });
    return counts;
  }, [scansData]);

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
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.4rem', fontWeight: 700, color: '#e6edf3' }}>Scans</h1>
          <p style={{ margin: '0.25rem 0 0', fontSize: '0.85rem', color: C.muted }}>
            Scan history and status
          </p>
        </div>
        <button
          onClick={() => navigate('/scans/start')}
          style={{
            background: C.accent,
            border: 'none',
            borderRadius: '6px',
            color: '#0d1117',
            cursor: 'pointer',
            fontSize: '0.875rem',
            fontWeight: 600,
            padding: '0.5rem 1.25rem',
            transition: 'opacity 0.15s ease',
          }}
          onMouseEnter={e => e.currentTarget.style.opacity = '0.85'}
          onMouseLeave={e => e.currentTarget.style.opacity = '1'}
        >
          + New Scan
        </button>
      </div>

      {/* ── Status summary pills ── */}
      {!loading && scansData && (
        <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.25rem', flexWrap: 'wrap' }}>
          {[
            { key: 'running',   color: '#2563eb' },
            { key: 'completed', color: '#16a34a' },
            { key: 'failed',    color: '#dc2626' },
            { key: 'pending',   color: '#ca8a04' },
          ].map(({ key, color }) =>
            statusCounts[key] != null ? (
              <span key={key} style={{
                display: 'inline-flex', alignItems: 'center', gap: '4px',
                padding: '3px 10px',
                borderRadius: '9999px',
                fontSize: '0.78rem',
                fontWeight: 600,
                background: color + '22',
                color: color,
                border: `1px solid ${color}44`,
              }}>
                {key.charAt(0).toUpperCase() + key.slice(1)}: {statusCounts[key]}
              </span>
            ) : null
          )}
        </div>
      )}

      {/* ── Filter bar ── */}
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
        <input
          type="text"
          value={domainInput}
          onChange={e => setDomainInput(e.target.value)}
          placeholder="Domain…"
          style={{
            flex: '1',
            minWidth: '160px',
            maxWidth: '280px',
            background: C.bg,
            border: `1px solid ${C.border}`,
            borderRadius: '6px',
            color: C.text,
            fontSize: '0.875rem',
            padding: '0.35rem 0.75rem',
            outline: 'none',
          }}
          onFocus={e => e.currentTarget.style.borderColor = C.accent}
          onBlur={e => e.currentTarget.style.borderColor = C.border}
        />
        <select
          value={currentStatus}
          onChange={handleStatusChange}
          style={{
            background: C.bg,
            border: `1px solid ${C.border}`,
            borderRadius: '6px',
            color: currentStatus ? C.text : C.muted,
            fontSize: '0.875rem',
            padding: '0.35rem 0.75rem',
            outline: 'none',
            cursor: 'pointer',
          }}
          onFocus={e => e.currentTarget.style.borderColor = C.accent}
          onBlur={e => e.currentTarget.style.borderColor = C.border}
        >
          <option value="">All statuses</option>
          {STATUS_OPTIONS.filter(Boolean).map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>
        {(currentDomain || currentStatus) && (
          <button
            onClick={() => { setDomainInput(''); navigate('/scans'); }}
            style={{
              background: 'none', border: `1px solid ${C.border}`, borderRadius: '6px',
              color: C.muted, cursor: 'pointer', fontSize: '0.8rem', padding: '0.3rem 0.75rem',
            }}
          >
            Clear
          </button>
        )}
      </div>

      {/* ── Scans table ── */}
      <div style={{
        backgroundColor: C.card,
        border: `1px solid ${C.border}`,
        borderRadius: '10px',
        overflow: 'hidden',
        marginBottom: '1.5rem',
      }}>
        {loading ? (
          <div style={{ padding: '2rem', display: 'flex', justifyContent: 'center' }}><Spinner /></div>
        ) : error ? (
          <div style={{ padding: '2rem', color: C.danger }}>Error: {error}</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {['Domain', 'Status', 'Start Time', 'Duration', 'Findings', 'Actions'].map(h => (
                  <th key={h} style={thStyle}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {scansData && scansData.length > 0 ? (
                scansData.map((scan, i) => {
                  const busy = busyUuids.has(scan.uuid);
                  const isLast = i === scansData.length - 1;
                  const duration = fmtDuration(scan.start_time, scan.end_time);
                  return (
                    <tr
                      key={scan.uuid}
                      style={{
                        borderBottom: isLast ? 'none' : `1px solid ${C.border}`,
                        transition: 'background-color 0.1s ease',
                        opacity: busy ? 0.6 : 1,
                      }}
                      onMouseEnter={e => e.currentTarget.style.backgroundColor = '#1c2128'}
                      onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
                    >
                      {/* Domain */}
                      <td style={{ ...tdStyle, color: '#e6edf3', fontWeight: 500 }}>
                        {scan.domain_name || scan.domain || '—'}
                      </td>

                      {/* Status */}
                      <td style={tdStyle}>
                        <Badge value={scan.status} />
                      </td>

                      {/* Start Time */}
                      <td style={{ ...tdStyle, color: C.muted, fontSize: '0.82rem' }}>
                        {fmtDate(scan.start_time)}
                      </td>

                      {/* Duration */}
                      <td style={{ ...tdStyle, color: C.muted, fontSize: '0.82rem' }}>
                        {scan.status === 'running' ? (
                          <span style={{ color: '#2563eb' }}>running…</span>
                        ) : (
                          duration || <span style={{ color: C.muted }}>—</span>
                        )}
                      </td>

                      {/* Findings */}
                      <td style={tdStyle}>
                        <FindingsSummary total={scan.total_findings} />
                      </td>

                      {/* Actions */}
                      <td style={tdStyle}>
                        <span style={{ display: 'inline-flex', gap: '6px', alignItems: 'center' }}>
                          <button
                            onClick={() => navigate(`/scans/${scan.uuid}`)}
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
                          {scan.status !== 'running' && scan.status !== 'pending' && (
                            <DeleteButton onConfirm={() => handleDelete(scan.uuid)} />
                          )}
                        </span>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={6} style={{ padding: '2.5rem', textAlign: 'center', color: C.muted }}>
                    {currentDomain || currentStatus ? 'No scans match these filters.' : 'No scans yet.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* ── Pagination ── */}
      {!loading && (
        <Pagination
          pagination={pagination}
          basePath="/scans"
          params={{
            ...(currentDomain ? { domain: currentDomain } : {}),
            ...(currentStatus ? { status: currentStatus } : {}),
          }}
        />
      )}

      {/* ── Scheduled Jobs ── */}
      <div style={{ marginTop: '2rem' }}>
        <h2 style={{
          color: C.muted,
          fontSize: '0.85rem',
          fontWeight: 600,
          letterSpacing: '0.06em',
          textTransform: 'uppercase',
          margin: '0 0 0.75rem',
        }}>
          Scheduled Jobs
        </h2>
        <div style={{
          backgroundColor: C.card,
          border: `1px solid ${C.border}`,
          borderRadius: '10px',
          overflow: 'hidden',
        }}>
          {schedLoading ? (
            <div style={{ padding: '1.5rem', display: 'flex', justifyContent: 'center' }}><Spinner /></div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                  {['Domain', 'Type', 'Frequency', 'Next Run', 'Actions'].map(h => (
                    <th key={h} style={thStyle}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {scheduledData && scheduledData.length > 0 ? (
                  scheduledData.map((job, i) => (
                    <tr
                      key={job.job_id}
                      style={{
                        borderBottom: i === scheduledData.length - 1 ? 'none' : `1px solid ${C.border}`,
                        transition: 'background-color 0.1s ease',
                      }}
                      onMouseEnter={e => e.currentTarget.style.backgroundColor = '#1c2128'}
                      onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
                    >
                      <td style={{ ...tdStyle, color: '#e6edf3', fontWeight: 500 }}>{job.domain}</td>
                      <td style={{ ...tdStyle, color: C.muted }}>{job.job_type}</td>
                      <td style={{ ...tdStyle, color: C.muted }}>{job.frequency}</td>
                      <td style={{ ...tdStyle, color: C.muted, fontSize: '0.82rem' }}>{fmtDate(job.next_run_time)}</td>
                      <td style={tdStyle}>
                        <button
                          onClick={() => handleCancelJob(job.job_id)}
                          style={{
                            background: 'none', border: `1px solid ${C.border}`, borderRadius: '6px',
                            color: C.text, cursor: 'pointer', fontSize: '0.8rem', padding: '0.3rem 0.75rem',
                            transition: 'border-color 0.15s ease, color 0.15s ease',
                          }}
                          onMouseEnter={e => { e.currentTarget.style.borderColor = C.danger; e.currentTarget.style.color = C.danger; }}
                          onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.text; }}
                        >
                          Cancel
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} style={{ padding: '2rem', textAlign: 'center', color: C.muted }}>
                      No scheduled jobs.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
