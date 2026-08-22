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

  return (
    <div className={`text-[11px] text-dim/70 text-center select-none ${className}`}>
      {parts.join(' · ')}
    </div>
  );
}
