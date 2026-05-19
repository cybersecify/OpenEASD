import React from 'react';
import { cva } from 'class-variance-authority';
import { cn } from '../lib/utils.js';

const badgeVariants = cva(
  'inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold capitalize border',
  {
    variants: {
      variant: {
        critical:       'bg-red-900/40 text-red-400 border-red-800',
        high:           'bg-orange-900/40 text-orange-400 border-orange-800',
        medium:         'bg-yellow-900/40 text-yellow-400 border-yellow-800',
        low:            'bg-blue-900/40 text-blue-400 border-blue-800',
        info:           'bg-gray-800/60 text-gray-400 border-gray-700',
        pending:        'bg-gray-800/60 text-gray-400 border-gray-700',
        running:        'bg-blue-900/40 text-blue-400 border-blue-800',
        completed:      'bg-green-900/40 text-green-400 border-green-800',
        failed:         'bg-red-900/40 text-red-400 border-red-800',
        cancelled:      'bg-gray-800/60 text-gray-400 border-gray-700',
        scheduled:      'bg-yellow-900/40 text-yellow-400 border-yellow-800',
        open:           'bg-red-900/40 text-red-400 border-red-800',
        acknowledged:   'bg-yellow-900/40 text-yellow-400 border-yellow-800',
        in_progress:    'bg-blue-900/40 text-blue-400 border-blue-800',
        resolved:       'bg-green-900/40 text-green-400 border-green-800',
        false_positive: 'bg-gray-800/60 text-gray-400 border-gray-700',
        active:         'bg-green-900/40 text-green-400 border-green-800',
        inactive:       'bg-gray-800/60 text-gray-400 border-gray-700',
        idle:           'bg-gray-800/60 text-gray-400 border-gray-700',
        web:            'bg-blue-900/40 text-blue-400 border-blue-800',
        fallback:       'bg-gray-800/60 text-gray-400 border-gray-700',
      },
    },
    defaultVariants: { variant: 'fallback' },
  }
);

const KNOWN = new Set([
  'critical','high','medium','low','info','pending','running','completed','failed',
  'cancelled','scheduled','open','acknowledged','in_progress','resolved',
  'false_positive','active','inactive','idle','web',
]);

export function Badge({ value }) {
  const label   = value ?? '—';
  const variant = KNOWN.has(label) ? label : 'fallback';
  return (
    <span className={cn(badgeVariants({ variant }))}>
      {label.replace(/_/g, ' ')}
    </span>
  );
}
