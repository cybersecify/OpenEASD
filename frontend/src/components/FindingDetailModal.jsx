import React, { useState } from 'react';
import { Badge } from './Badge.jsx';
import { apiPost } from '../api/client.js';
import { toast } from './Notification.jsx';
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogTitle,
} from './ui/alert-dialog.jsx';

// Detail view for a single Finding, opened from the Scan Detail findings tab.
// The row already carries the full record (description, remediation, extra, …),
// so it renders from the passed object — no extra fetch. Finding status
// (triage) is editable here, so lifecycle management lives with the scan.

const STATUSES = ['open', 'acknowledged', 'in_progress', 'resolved', 'false_positive'];

function fmtDateTime(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

function Meta({ label, children }) {
  return (
    <div>
      <div className="text-xs font-semibold uppercase tracking-wider text-dim">{label}</div>
      <div className="text-body text-sm mt-0.5 break-words">{children}</div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div>
      <div className="text-xs font-semibold uppercase tracking-wider text-dim mb-1">{title}</div>
      {children}
    </div>
  );
}

// Pull the well-known CVE/exploitability fields out of `extra` and show them as
// labelled chips; the rest of `extra` falls through to a generic key/value list.
const KNOWN_EXTRA = new Set([
  'cve', 'cve_id', 'cve_ids', 'cvss', 'cvss_score', 'epss', 'epss_score',
  'kev', 'cisa_kev', 'is_kev',
]);

function ExtraDetails({ extra }) {
  if (!extra || typeof extra !== 'object' || Object.keys(extra).length === 0) return null;

  const cves = []
    .concat(extra.cve_ids || [])
    .concat(extra.cve ? [extra.cve] : [])
    .concat(extra.cve_id ? [extra.cve_id] : []);
  const uniqueCves = [...new Set(cves.filter(Boolean))];
  const cvss = extra.cvss_score ?? extra.cvss;
  const epss = extra.epss_score ?? extra.epss;
  const isKev = extra.kev ?? extra.cisa_kev ?? extra.is_kev;

  const chips = [];
  if (cvss != null) chips.push(['CVSS', String(cvss)]);
  if (epss != null) {
    const pct = typeof epss === 'number' && epss <= 1 ? `${(epss * 100).toFixed(1)}%` : String(epss);
    chips.push(['EPSS', pct]);
  }
  if (isKev) chips.push(['CISA KEV', 'yes']);

  // Remaining keys not already surfaced above.
  const rest = Object.entries(extra).filter(([k, v]) =>
    !KNOWN_EXTRA.has(k) && v != null && v !== '' && !(Array.isArray(v) && v.length === 0));

  if (!uniqueCves.length && !chips.length && !rest.length) return null;

  return (
    <Section title="Vulnerability Intelligence">
      <div className="space-y-2">
        {uniqueCves.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {uniqueCves.map(cve => (
              <span key={cve} className="rounded-md border border-red-800 bg-red-900/20 text-red-300 text-xs font-mono px-2 py-0.5">{cve}</span>
            ))}
          </div>
        )}
        {chips.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {chips.map(([k, v]) => (
              <span key={k} className="rounded-md border border-rim bg-canvas text-xs px-2 py-0.5">
                <span className="text-dim">{k}: </span><span className="text-body font-semibold">{v}</span>
              </span>
            ))}
          </div>
        )}
        {rest.length > 0 && (
          <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-xs">
            {rest.map(([k, v]) => (
              <React.Fragment key={k}>
                <dt className="text-dim font-mono">{k}</dt>
                <dd className="text-body break-words font-mono">
                  {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                </dd>
              </React.Fragment>
            ))}
          </dl>
        )}
      </div>
    </Section>
  );
}

export function FindingDetailModal({ finding, onClose, onStatusChanged }) {
  const [status, setStatus] = useState(finding?.status || 'open');
  const [saving, setSaving] = useState(false);
  if (!finding) return null;
  const f = finding;

  async function changeStatus(next) {
    setStatus(next);
    setSaving(true);
    try {
      await apiPost(`/findings/${f.id}/status/`, { status: next });
      toast.success('Status updated.');
      onStatusChanged && onStatusChanged();
    } catch (err) {
      setStatus(f.status || 'open');   // revert on failure
      toast.error(err.message || 'Failed to update status.');
    } finally { setSaving(false); }
  }

  return (
    <AlertDialog open onOpenChange={open => !open && onClose()}>
      <AlertDialogContent className="bg-card border border-rim max-w-2xl max-h-[85vh] overflow-y-auto">
        <AlertDialogHeader>
          <div className="flex items-start gap-3">
            <Badge value={f.severity} />
            <AlertDialogTitle className="text-lit text-base leading-snug">{f.title}</AlertDialogTitle>
          </div>
        </AlertDialogHeader>

        <div className="space-y-4 py-1 text-left">
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <Meta label="Source"><span className="font-mono text-xs">{f.source || '—'}</span></Meta>
            <Meta label="Check type"><span className="font-mono text-xs">{f.check_type || '—'}</span></Meta>
            <Meta label="Status">
              <select value={status} onChange={e => changeStatus(e.target.value)} disabled={saving}
                className="field text-xs py-0.5 px-1.5 w-auto">
                {STATUSES.map(s => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
              </select>
            </Meta>
            <Meta label="Target"><span className="font-mono text-xs break-all">{f.target || '—'}</span></Meta>
            {f.asset_key && <Meta label="Asset"><span className="font-mono text-xs break-all">{f.asset_key}</span></Meta>}
            <Meta label="Discovered">{fmtDateTime(f.discovered_at)}</Meta>
          </div>

          {f.description && (
            <Section title="Description">
              <p className="text-body text-sm whitespace-pre-wrap break-words">{f.description}</p>
            </Section>
          )}

          {f.remediation && (
            <Section title="Remediation">
              <p className="text-body text-sm whitespace-pre-wrap break-words">{f.remediation}</p>
            </Section>
          )}

          <ExtraDetails extra={f.extra} />

          {f.resolution_note && (
            <Section title="Resolution note">
              <p className="text-body text-sm whitespace-pre-wrap break-words">{f.resolution_note}</p>
            </Section>
          )}
        </div>

        <div className="flex justify-end pt-2 border-t border-rim">
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded-md text-sm text-dim hover:text-body hover:bg-hover transition-colors">
            Close
          </button>
        </div>
      </AlertDialogContent>
    </AlertDialog>
  );
}
