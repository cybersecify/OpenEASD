import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiGet } from '../api/client.js';

/**
 * Muted footer line showing the running build's provenance, e.g.
 *   OpenEASD v0.10.0 · a1b2c3d4 · 2026-08-22
 * Data comes from the unauthenticated GET /api/version/. Local (non-image)
 * runs report "dev"/"unknown" defaults, which are omitted so the line never
 * reads "unknown · unknown".
 */
export default function BuildInfo({ className = '' }) {
  const { data } = useQuery({
    queryKey: ['/version/'],
    queryFn: () => apiGet('/version/'),
    staleTime: Infinity,
  });

  if (!data) return null;

  const parts = [`OpenEASD ${data.version === 'dev' ? 'dev' : `v${data.version}`}`];
  if (data.git_sha_short && data.git_sha_short !== 'unknown') {
    parts.push(data.git_sha_short);
  }
  if (data.build_date && data.build_date !== 'unknown') {
    parts.push(String(data.build_date).split('T')[0]);
  }
  const buildLine = parts.join(' · ');

  // Pre-fill new-issue reports with the running build so we never have to ask
  // "what version are you on?". GitHub Issues is the OSS-native report channel.
  const ISSUES = 'https://github.com/cybersecify/OpenEASD/issues/new';
  const env = encodeURIComponent(`\n\n---\nBuild (auto-filled): ${buildLine}`);
  const bugUrl = `${ISSUES}?labels=bug&title=${encodeURIComponent('[Bug] ')}&body=${env}`;
  const featureUrl = `${ISSUES}?labels=enhancement&title=${encodeURIComponent('[Feature] ')}&body=${env}`;

  return (
    <div className={`text-[11px] text-dim/70 text-center select-none space-y-0.5 ${className}`}>
      <div>{buildLine}</div>
      <div className="space-x-2">
        <a href={bugUrl} target="_blank" rel="noopener noreferrer" className="underline hover:text-dim">Report an issue</a>
        <span aria-hidden="true">·</span>
        <a href={featureUrl} target="_blank" rel="noopener noreferrer" className="underline hover:text-dim">Request a feature</a>
      </div>
    </div>
  );
}
