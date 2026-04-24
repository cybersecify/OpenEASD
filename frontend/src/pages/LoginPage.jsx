import React, { useState } from 'react';
import { apiPost } from '../api/client.js';
import { auth } from '../auth.js';
import { navigate } from '../App.jsx';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error,    setError]    = useState(null);
  const [loading,  setLoading]  = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await apiPost('/token/pair', { username, password });
      auth.setTokens(res.access, res.refresh);
      navigate('/');
    } catch (err) {
      setError(err.data?.error?.message || err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-canvas flex items-center justify-center font-sans">
      <div className="w-full max-w-sm bg-card border border-rim rounded-xl p-8 shadow-xl">
        <h1 className="text-lit font-bold text-xl text-center mb-6">OpenEASD</h1>
        {error && (
          <div className="mb-4 px-3 py-2 rounded-md bg-red-900/40 border border-red-700 text-red-400 text-sm">
            {error}
          </div>
        )}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs text-dim mb-1 font-medium">Username</label>
            <input type="text" value={username} onChange={e => setUsername(e.target.value)}
              autoComplete="username" required className="field" />
          </div>
          <div>
            <label className="block text-xs text-dim mb-1 font-medium">Password</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)}
              autoComplete="current-password" required className="field" />
          </div>
          <button type="submit" disabled={loading} className="btn-primary w-full mt-2">
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
}
