import React from 'react';
import { navigate } from '../App.jsx';

export function Pagination({ pagination, basePath, params = {} }) {
  if (!pagination || pagination.total_pages <= 1) return null;

  const buildUrl = (page) => {
    const p = new URLSearchParams({ ...params, page });
    return `${basePath}?${p.toString()}`;
  };

  return (
    <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginTop: '1rem' }}>
      {pagination.has_previous && (
        <button onClick={() => navigate(buildUrl(pagination.page - 1))}>← Prev</button>
      )}
      <span>Page {pagination.page} of {pagination.total_pages} ({pagination.count} total)</span>
      {pagination.has_next && (
        <button onClick={() => navigate(buildUrl(pagination.page + 1))}>Next →</button>
      )}
    </div>
  );
}
