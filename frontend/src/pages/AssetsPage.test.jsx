import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SeverityChips } from './AssetsPage.jsx';

describe('SeverityChips', () => {
  it('renders a chip only for non-zero severities', () => {
    render(<SeverityChips counts={{ critical: 2, high: 0, medium: 1, low: 0, info: 0 }} />);
    expect(screen.getByText('2 critical')).toBeInTheDocument();
    expect(screen.getByText('1 medium')).toBeInTheDocument();
    expect(screen.queryByText(/high/)).not.toBeInTheDocument();
  });

  it('renders an em dash when there are no findings', () => {
    render(<SeverityChips counts={{ critical: 0, high: 0, medium: 0, low: 0, info: 0 }} />);
    expect(screen.getByText('—')).toBeInTheDocument();
  });

  it('handles a missing counts object', () => {
    render(<SeverityChips counts={undefined} />);
    expect(screen.getByText('—')).toBeInTheDocument();
  });
});
