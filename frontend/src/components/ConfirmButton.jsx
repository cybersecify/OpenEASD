import React, { useState } from 'react';

export function ConfirmButton({ onConfirm, label = 'Delete', confirmLabel = 'Confirm?', cancelLabel = 'Cancel', danger = true }) {
  const [confirming, setConfirming] = useState(false);

  if (confirming) {
    return (
      <span>
        <button onClick={() => { setConfirming(false); onConfirm(); }}
          style={{ color: danger ? '#dc2626' : undefined, marginRight: '4px' }}>
          {confirmLabel}
        </button>
        <button onClick={() => setConfirming(false)}>{cancelLabel}</button>
      </span>
    );
  }

  return (
    <button onClick={() => setConfirming(true)}>{label}</button>
  );
}
