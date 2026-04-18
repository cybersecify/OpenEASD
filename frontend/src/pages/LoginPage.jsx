import React, { useState } from 'react';
import { apiPost } from '../api/client.js';
import { navigate } from '../App.jsx';

const styles = {
  page: {
    minHeight: '100vh',
    backgroundColor: '#0d1117',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontFamily: "'Segoe UI', system-ui, -apple-system, sans-serif",
  },
  card: {
    backgroundColor: '#161b22',
    border: '1px solid #30363d',
    borderRadius: '12px',
    padding: '2.5rem 2rem',
    width: '100%',
    maxWidth: '380px',
  },
  logoArea: {
    textAlign: 'center',
    marginBottom: '2rem',
  },
  logoIcon: {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '52px',
    height: '52px',
    borderRadius: '12px',
    backgroundColor: '#30c07422',
    border: '1px solid #30c07444',
    marginBottom: '1rem',
  },
  title: {
    color: '#e6edf3',
    fontSize: '1.5rem',
    fontWeight: 700,
    margin: '0 0 0.25rem',
    letterSpacing: '-0.02em',
  },
  subtitle: {
    color: '#8b949e',
    fontSize: '0.8rem',
    margin: 0,
    letterSpacing: '0.04em',
    textTransform: 'uppercase',
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem',
  },
  fieldGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.375rem',
  },
  label: {
    color: '#8b949e',
    fontSize: '0.8rem',
    fontWeight: 500,
    letterSpacing: '0.02em',
  },
  input: {
    backgroundColor: '#0d1117',
    border: '1px solid #30363d',
    borderRadius: '6px',
    color: '#e6edf3',
    fontSize: '0.9rem',
    padding: '0.625rem 0.75rem',
    outline: 'none',
    transition: 'border-color 0.15s ease',
    width: '100%',
    boxSizing: 'border-box',
  },
  inputFocus: {
    borderColor: '#30c074',
  },
  button: {
    backgroundColor: '#30c074',
    border: 'none',
    borderRadius: '6px',
    color: '#0d1117',
    cursor: 'pointer',
    fontSize: '0.9rem',
    fontWeight: 600,
    marginTop: '0.5rem',
    padding: '0.7rem',
    transition: 'background-color 0.15s ease, opacity 0.15s ease',
    width: '100%',
  },
  buttonDisabled: {
    opacity: 0.6,
    cursor: 'not-allowed',
  },
  errorBox: {
    backgroundColor: '#dc262622',
    border: '1px solid #dc262644',
    borderRadius: '6px',
    color: '#f87171',
    fontSize: '0.85rem',
    padding: '0.625rem 0.75rem',
  },
};

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [focusedField, setFocusedField] = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await apiPost('/auth/login/', { username, password });
      navigate('/');
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  function inputStyle(field) {
    return {
      ...styles.input,
      ...(focusedField === field ? styles.inputFocus : {}),
    };
  }

  return (
    <div style={styles.page}>
      <div style={styles.card}>
        <div style={styles.logoArea}>
          <div style={styles.logoIcon}>
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"
                stroke="#30c074" strokeWidth="1.75" strokeLinejoin="round" fill="#30c07418" />
              <circle cx="12" cy="12" r="3" fill="#30c074" />
            </svg>
          </div>
          <h1 style={styles.title}>OpenEASD</h1>
          <p style={styles.subtitle}>External Attack Surface Detection</p>
        </div>

        <form onSubmit={handleSubmit} style={styles.form}>
          {error && <div style={styles.errorBox}>{error}</div>}

          <div style={styles.fieldGroup}>
            <label style={styles.label} htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              onFocus={() => setFocusedField('username')}
              onBlur={() => setFocusedField(null)}
              style={inputStyle('username')}
              autoComplete="username"
              required
            />
          </div>

          <div style={styles.fieldGroup}>
            <label style={styles.label} htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              onFocus={() => setFocusedField('password')}
              onBlur={() => setFocusedField(null)}
              style={inputStyle('password')}
              autoComplete="current-password"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{ ...styles.button, ...(loading ? styles.buttonDisabled : {}) }}
          >
            {loading ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
}
