import React, { useState } from 'react';

export function ConfirmButton({ label = 'Delete', confirmLabel = 'Confirm', onConfirm, disabled }) {
  const [confirming, setConfirming] = useState(false);
  if (confirming) {
    return (
      <span className="inline-flex gap-1.5 items-center">
        <button
          onClick={() => { setConfirming(false); onConfirm(); }}
          className="bg-transparent border border-red-600 text-red-400 text-xs px-2.5 py-1 rounded-md hover:bg-red-900/20 transition-colors"
        >
          {confirmLabel}
        </button>
        <button onClick={() => setConfirming(false)} className="btn-ghost text-xs px-2.5 py-1">Cancel</button>
      </span>
    );
  }
  return (
    <button disabled={disabled} onClick={() => setConfirming(true)} className="btn-danger">
      {label}
    </button>
  );
}
