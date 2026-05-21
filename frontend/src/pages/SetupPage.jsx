import React, { useState } from 'react';
import { Button } from '../components/ui/button.jsx';
import { apiPost } from '../api/client.js';
import { navigate } from '../App.jsx';

export default function SetupPage() {
  const [step, setStep] = useState(1);

  const [current,  setCurrent]  = useState('');
  const [next,     setNext]     = useState('');
  const [confirm,  setConfirm]  = useState('');
  const [pwError,  setPwError]  = useState(null);
  const [pwLoading,setPwLoading]= useState(false);

  const [domain,    setDomain]    = useState('');
  const [domError,  setDomError]  = useState(null);
  const [domLoading,setDomLoading]= useState(false);

  async function handlePassword(e) {
    e.preventDefault();
    setPwError(null);
    if (next !== confirm) { setPwError('Passwords do not match'); return; }
    if (next.length < 8)  { setPwError('Password must be at least 8 characters'); return; }
    setPwLoading(true);
    try {
      await apiPost('/user/change-password/', { current_password: current, new_password: next });
      setStep(2);
    } catch (err) {
      setPwError(err.data?.error?.message || err.message || 'Failed to change password');
    } finally {
      setPwLoading(false);
    }
  }

  async function handleDomain(e) {
    e.preventDefault();
    setDomError(null);
    setDomLoading(true);
    try {
      await apiPost('/domains/', { name: domain.trim().toLowerCase() });
      navigate('/');
    } catch (err) {
      setDomError(err.data?.error?.message || err.message || 'Failed to add domain');
    } finally {
      setDomLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-canvas flex items-center justify-center font-sans">
      <div className="w-full max-w-md bg-card border border-rim rounded-xl p-8 shadow-xl">

        {/* Step indicator */}
        <div className="flex items-center mb-8">
          <div className="flex items-center gap-2">
            <span className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold transition-colors ${step >= 1 ? 'bg-brand text-canvas' : 'bg-rim text-dim'}`}>
              1
            </span>
            <span className={`text-xs font-medium ${step === 1 ? 'text-lit' : 'text-dim'}`}>Set Password</span>
          </div>
          <div className="flex-1 h-px bg-rim mx-4" />
          <div className="flex items-center gap-2">
            <span className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold transition-colors ${step >= 2 ? 'bg-brand text-canvas' : 'bg-rim text-dim'}`}>
              2
            </span>
            <span className={`text-xs font-medium ${step === 2 ? 'text-lit' : 'text-dim'}`}>Add Domain</span>
          </div>
        </div>

        {step === 1 && (
          <>
            <h1 className="text-lit font-bold text-xl mb-1">Welcome to OpenEASD</h1>
            <p className="text-dim text-sm mb-6">
              First-time login uses <code className="font-mono text-lit">admin</code> / <code className="font-mono text-lit">admin</code>. Enter it once below to confirm, then set your new password.
            </p>
            {pwError && (
              <div className="mb-4 px-3 py-2 rounded-md bg-red-900/40 border border-red-700 text-red-400 text-sm">
                {pwError}
              </div>
            )}
            <form onSubmit={handlePassword} className="space-y-4">
              <div>
                <label className="block text-xs text-dim mb-1 font-medium">Current Password</label>
                <input
                  type="password"
                  value={current}
                  onChange={e => setCurrent(e.target.value)}
                  autoComplete="current-password"
                  required
                  className="field"
                />
              </div>
              <div>
                <label className="block text-xs text-dim mb-1 font-medium">New Password</label>
                <input
                  type="password"
                  value={next}
                  onChange={e => setNext(e.target.value)}
                  autoComplete="new-password"
                  required
                  className="field"
                />
              </div>
              <div>
                <label className="block text-xs text-dim mb-1 font-medium">Confirm New Password</label>
                <input
                  type="password"
                  value={confirm}
                  onChange={e => setConfirm(e.target.value)}
                  autoComplete="new-password"
                  required
                  className="field"
                />
              </div>
              <Button type="submit" disabled={pwLoading} className="w-full mt-2">
                {pwLoading ? 'Saving…' : 'Continue →'}
              </Button>
            </form>
          </>
        )}

        {step === 2 && (
          <>
            <h1 className="text-lit font-bold text-xl mb-1">Add Your First Domain</h1>
            <p className="text-dim text-sm mb-6">
              Enter the root domain you want to scan for attack surface exposure.
            </p>
            {domError && (
              <div className="mb-4 px-3 py-2 rounded-md bg-red-900/40 border border-red-700 text-red-400 text-sm">
                {domError}
              </div>
            )}
            <form onSubmit={handleDomain} className="space-y-4">
              <div>
                <label className="block text-xs text-dim mb-1 font-medium">Domain</label>
                <input
                  type="text"
                  value={domain}
                  onChange={e => setDomain(e.target.value)}
                  placeholder="example.com"
                  autoComplete="off"
                  required
                  className="field"
                />
                <p className="mt-1 text-xs text-dim">Root domain only — no https:// or paths</p>
              </div>
              <Button type="submit" disabled={domLoading} className="w-full">
                {domLoading ? 'Adding…' : 'Add Domain'}
              </Button>
              <Button
                type="button"
                variant="ghost"
                className="w-full text-dim hover:text-lit"
                onClick={() => navigate('/')}
              >
                Skip for now
              </Button>
            </form>
          </>
        )}

      </div>
    </div>
  );
}
