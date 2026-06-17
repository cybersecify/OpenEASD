import React, { useState } from 'react';
import { Button } from '../components/ui/button.jsx';
import { apiPost } from '../api/client.js';
import { useNavigate } from 'react-router-dom';

export default function ChangePasswordPage() {
  const navigate = useNavigate();
  const [current,  setCurrent]  = useState('');
  const [next,     setNext]     = useState('');
  const [confirm,  setConfirm]  = useState('');
  const [error,    setError]    = useState(null);
  const [loading,  setLoading]  = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    if (next !== confirm) { setError('Passwords do not match'); return; }
    if (next.length < 8)  { setError('Password must be at least 8 characters'); return; }
    setLoading(true);
    try {
      await apiPost('/user/change-password/', { current_password: current, new_password: next });
      navigate('/');
    } catch (err) {
      setError(err.data?.error?.message || err.message || 'Failed to change password');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-canvas flex items-center justify-center font-sans">
      <div className="w-full max-w-sm bg-card border border-rim rounded-xl p-8 shadow-xl">
        <h1 className="text-lit font-bold text-xl text-center mb-2">Change Password</h1>
        <p className="text-dim text-sm text-center mb-6">
          You must set a new password before continuing.
        </p>
        {error && (
          <div className="mb-4 px-3 py-2 rounded-md bg-red-900/40 border border-red-700 text-red-400 text-sm">
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs text-dim mb-1 font-medium">Current Password</label>
            <input type="password" value={current} onChange={e => setCurrent(e.target.value)}
              autoComplete="current-password" required className="field" />
          </div>
          <div>
            <label className="block text-xs text-dim mb-1 font-medium">New Password</label>
            <input type="password" value={next} onChange={e => setNext(e.target.value)}
              autoComplete="new-password" required className="field" />
          </div>
          <div>
            <label className="block text-xs text-dim mb-1 font-medium">Confirm New Password</label>
            <input type="password" value={confirm} onChange={e => setConfirm(e.target.value)}
              autoComplete="new-password" required className="field" />
          </div>
          <Button type="submit" disabled={loading} className="w-full mt-2">
            {loading ? 'Saving…' : 'Set New Password'}
          </Button>
        </form>
      </div>
    </div>
  );
}
