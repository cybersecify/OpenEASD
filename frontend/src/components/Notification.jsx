import React, { useEffect, useState } from 'react';

export function Notification({ message, type = 'success', duration = 4000 }) {
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    const t = setTimeout(() => setVisible(false), duration);
    return () => clearTimeout(t);
  }, [duration]);

  if (!visible || !message) return null;

  const colors = {
    success: { bg: '#052e16', border: '#16a34a', text: '#4ade80' },
    error: { bg: '#450a0a', border: '#dc2626', text: '#f87171' },
    info: { bg: '#0c1a2e', border: '#2563eb', text: '#60a5fa' },
  };
  const c = colors[type] || colors.info;

  return (
    <div style={{
      position: 'fixed', top: '1rem', right: '1rem', zIndex: 9999,
      padding: '0.75rem 1.25rem', borderRadius: '8px',
      background: c.bg, border: `1px solid ${c.border}`, color: c.text,
      maxWidth: '380px', boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
    }}>
      {message}
      <button onClick={() => setVisible(false)}
        style={{ marginLeft: '12px', background: 'none', border: 'none', color: c.text, cursor: 'pointer' }}>
        x
      </button>
    </div>
  );
}
