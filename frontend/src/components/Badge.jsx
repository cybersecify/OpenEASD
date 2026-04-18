import React from 'react';

const COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#2563eb',
  info: '#6b7280',
  completed: '#16a34a',
  running: '#2563eb',
  failed: '#dc2626',
  cancelled: '#6b7280',
  pending: '#ca8a04',
};

export function Badge({ value, label }) {
  const color = COLORS[value] || '#6b7280';
  return (
    <span style={{
      display: 'inline-block',
      padding: '2px 8px',
      borderRadius: '9999px',
      fontSize: '0.75rem',
      fontWeight: 600,
      background: color + '22',
      color: color,
      border: `1px solid ${color}44`,
    }}>
      {label || value}
    </span>
  );
}
