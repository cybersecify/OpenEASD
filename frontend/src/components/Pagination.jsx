import React from 'react';

export function Pagination({ page, totalPages, onPage }) {
  if (!totalPages || totalPages <= 1) return null;
  return (
    <div className="flex items-center justify-center gap-2 py-2">
      <button onClick={() => onPage(page - 1)} disabled={page <= 1} className="btn-ghost">← Prev</button>
      <span className="text-sm text-dim">Page {page} of {totalPages}</span>
      <button onClick={() => onPage(page + 1)} disabled={page >= totalPages} className="btn-ghost">Next →</button>
    </div>
  );
}
