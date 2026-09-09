import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Badge } from './Badge.jsx';

describe('Badge', () => {
  it('renders a known severity variant with its styling', () => {
    render(<Badge value="critical" />);
    const el = screen.getByText('critical');
    expect(el).toBeInTheDocument();
    expect(el.className).toContain('text-red-400');
  });

  it('replaces underscores in the displayed value', () => {
    render(<Badge value="false_positive" />);
    // Underscore-separated statuses render as spaced words.
    expect(screen.getByText('false positive')).toBeInTheDocument();
  });

  it('falls back to the fallback variant for an unknown value', () => {
    render(<Badge value="not_a_real_status" />);
    const el = screen.getByText('not a real status');
    expect(el.className).toContain('text-gray-400'); // fallback styling
  });

  it('uses an explicit label over the value when provided', () => {
    render(<Badge value="completed" label="All done" />);
    expect(screen.getByText('All done')).toBeInTheDocument();
    expect(screen.queryByText('completed')).not.toBeInTheDocument();
  });

  it('renders an em dash when value is nullish', () => {
    render(<Badge value={null} />);
    expect(screen.getByText('—')).toBeInTheDocument();
  });
});
