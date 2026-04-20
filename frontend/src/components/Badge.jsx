import React from 'react';

const CLS = {
  // severity
  critical:       'bg-red-900/40 text-red-400 border border-red-800',
  high:           'bg-orange-900/40 text-orange-400 border border-orange-800',
  medium:         'bg-yellow-900/40 text-yellow-400 border border-yellow-800',
  low:            'bg-blue-900/40 text-blue-400 border border-blue-800',
  info:           'bg-gray-800/60 text-gray-400 border border-gray-700',
  // scan status
  pending:        'bg-gray-800/60 text-gray-400 border border-gray-700',
  running:        'bg-blue-900/40 text-blue-400 border border-blue-800',
  completed:      'bg-green-900/40 text-green-400 border border-green-800',
  failed:         'bg-red-900/40 text-red-400 border border-red-800',
  cancelled:      'bg-gray-800/60 text-gray-400 border border-gray-700',
  scheduled:      'bg-yellow-900/40 text-yellow-400 border border-yellow-800',
  // finding status
  open:               'bg-red-900/40 text-red-400 border border-red-800',
  acknowledged:       'bg-yellow-900/40 text-yellow-400 border border-yellow-800',
  in_progress:        'bg-blue-900/40 text-blue-400 border border-blue-800',
  resolved:           'bg-green-900/40 text-green-400 border border-green-800',
  false_positive:     'bg-gray-800/60 text-gray-400 border border-gray-700',
  // domain/misc
  active:   'bg-green-900/40 text-green-400 border border-green-800',
  inactive: 'bg-gray-800/60 text-gray-400 border border-gray-700',
  idle:     'bg-gray-800/60 text-gray-400 border border-gray-700',
  web:      'bg-blue-900/40 text-blue-400 border border-blue-800',
};

const FALLBACK = 'bg-gray-800/60 text-gray-400 border border-gray-700';

export function Badge({ value }) {
  const label = value ?? '—';
  const cls   = CLS[label] ?? FALLBACK;
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold capitalize ${cls}`}>
      {label.replace(/_/g, ' ')}
    </span>
  );
}
