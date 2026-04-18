import React from 'react';

export function Badge({ value }) {
  const label = value ?? '—';
  const cls = `badge-${label.replace(/_/g, '-')}`;
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold capitalize ${cls}`}>
      {label.replace(/_/g, ' ')}
    </span>
  );
}
