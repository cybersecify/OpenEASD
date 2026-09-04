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
export default function BuildInfo({ className = '', checkUpdates = false, variant = 'footer' }) {
  const { data } = useQuery({
    queryKey: ['/version/'],
    queryFn: () => apiGet('/version/'),
    staleTime: Infinity,
  });

  // Only logged-in surfaces pass checkUpdates: the endpoint is authenticated and
  // hits GitHub (cached server-side). Fail-graceful — on any error we just don't
  // show the indicator, so the footer never breaks.
  const { data: latest } = useQuery({
    queryKey: ['/version/latest/'],
    queryFn: () => apiGet('/version/latest/'),
    enabled: checkUpdates,
    staleTime: 6 * 60 * 60 * 1000,
    retry: false,
  });

  if (!data) return null;

  const versionLabel = data.version === 'dev' ? 'dev' : `v${data.version}`;
  const updateAvailable = checkUpdates && latest?.update_available;
  const releaseUrl = latest?.release_url || 'https://github.com/cybersecify/OpenEASD/releases/latest';

  // Compact, prominent variant for the app's top-right header. Shows just the
  // running version, muted, when current; when a newer release exists it becomes
  // a brand-colored "Update" pill linking to the GitHub release. Display-only —
  // the app never self-updates, this is purely a heads-up + link.
  if (variant === 'topbar') {
    return (
      <div className={`flex items-center gap-2 text-xs select-none ${className}`}>
        {updateAvailable ? (
          <a
            href={releaseUrl}
            target="_blank"
            rel="noopener noreferrer"
            title={`OpenEASD ${versionLabel} → v${latest.latest_version} available on GitHub`}
            className="inline-flex items-center gap-1 rounded-full border border-brand/40 bg-brand/10 px-2.5 py-1 font-semibold text-brand hover:bg-brand/20 transition-colors whitespace-nowrap"
          >
            <span aria-hidden="true">↑</span>
            <span>Update v{latest.latest_version}</span>
          </a>
        ) : (
          <span className="text-dim/80 whitespace-nowrap" title="Running build">{versionLabel}</span>
        )}
      </div>
    );
  }

  const parts = [`OpenEASD ${data.version === 'dev' ? 'dev' : `v${data.version}`}`];
  if (data.git_sha_short && data.git_sha_short !== 'unknown') {
    parts.push(data.git_sha_short);
  }
  if (data.build_date && data.build_date !== 'unknown') {
    parts.push(String(data.build_date).split('T')[0]);
  }
  const buildLine = parts.join(' · ');

  // Pre-fill reports with the running build so we never have to ask "what
  // version are you on?". When a support email is configured (a branded
  // deployment), route to mailto: that inbox; otherwise fall back to GitHub
  // Issues (the OSS-native channel).
  const body = `\n\n---\nBuild (auto-filled): ${buildLine}`;
  let bugUrl, featureUrl;
  if (data.support_email) {
    const to = data.support_email;
    bugUrl = `mailto:${to}?subject=${encodeURIComponent('[Bug] ')}&body=${encodeURIComponent(body)}`;
    featureUrl = `mailto:${to}?subject=${encodeURIComponent('[Feature] ')}&body=${encodeURIComponent(body)}`;
  } else {
    const ISSUES = 'https://github.com/cybersecify/OpenEASD/issues/new';
    const env = encodeURIComponent(body);
    bugUrl = `${ISSUES}?labels=bug&title=${encodeURIComponent('[Bug] ')}&body=${env}`;
    featureUrl = `${ISSUES}?labels=enhancement&title=${encodeURIComponent('[Feature] ')}&body=${env}`;
  }

  return (
    <div className={`text-[11px] text-dim/70 text-center select-none space-y-0.5 ${className}`}>
      <div>{buildLine}</div>
      <div className="space-x-2">
        <a href={bugUrl} target="_blank" rel="noopener noreferrer" className="underline hover:text-dim">Report an issue</a>
        <span aria-hidden="true">·</span>
        <a href={featureUrl} target="_blank" rel="noopener noreferrer" className="underline hover:text-dim">Request a feature</a>
      </div>
      {checkUpdates && latest?.update_available && (
        <div>
          <a
            href={latest.release_url || 'https://github.com/cybersecify/OpenEASD/releases/latest'}
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand hover:underline font-medium"
          >
            ↑ Update available: v{latest.latest_version}
          </a>
        </div>
      )}
    </div>
  );
}
