import React, { useEffect, useState } from 'react';

export function Notification({ message, type = 'success' }) {
  const [visible, setVisible] = useState(true);
  useEffect(() => {
    const t = setTimeout(() => setVisible(false), 4000);
    return () => clearTimeout(t);
  }, []);
  if (!visible) return null;
  const cls = type === 'error'
    ? 'bg-red-900/50 border-red-700 text-red-300'
    : 'bg-green-900/50 border-green-700 text-green-300';
  return (
    <div className={`fixed top-4 right-4 z-50 px-4 py-3 rounded-lg border text-sm font-medium shadow-lg ${cls}`}>
      {message}
    </div>
  );
}
