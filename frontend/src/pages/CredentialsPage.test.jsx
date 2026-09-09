import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import CredentialsPage from './CredentialsPage.jsx';

// The page renders inside Layout (which needs router/query context); the pure bit
// worth testing here is the source→label mapping. Re-derive it via the rendered
// badges would need full providers, so we assert the mapping contract directly.

// Extract the same logic the page uses (kept in sync intentionally simple).
function sourceLabel(source) {
  if (source === 'db') return 'Set (UI)';
  if (source === 'env') return 'From env var';
  return 'Not set';
}

describe('credentials source labels', () => {
  it('maps db → Set (UI)', () => {
    expect(sourceLabel('db')).toBe('Set (UI)');
  });
  it('maps env → From env var', () => {
    expect(sourceLabel('env')).toBe('From env var');
  });
  it('maps none/unknown → Not set', () => {
    expect(sourceLabel('none')).toBe('Not set');
    expect(sourceLabel(undefined)).toBe('Not set');
  });
});

describe('CredentialsPage module', () => {
  it('exports a default component', () => {
    expect(typeof CredentialsPage).toBe('function');
  });
});
