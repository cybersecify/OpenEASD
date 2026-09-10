import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ExposureBadge, ExposureCard, gradeClasses } from './Exposure.jsx';

describe('gradeClasses', () => {
  it('maps good grades (A/B) to green and bad grades (F) to red', () => {
    expect(gradeClasses('A').text).toContain('green');
    expect(gradeClasses('B').text).toContain('brand');
    expect(gradeClasses('F').text).toContain('red');
  });

  it('is case-insensitive and falls back for unknown grades', () => {
    expect(gradeClasses('c').text).toBe(gradeClasses('C').text);
    expect(gradeClasses(null).text).toContain('body');
  });
});

describe('ExposureBadge', () => {
  it('renders the grade and score together', () => {
    render(<ExposureBadge score={27} grade="B" />);
    expect(screen.getByText('B')).toBeInTheDocument();
    expect(screen.getByText('27')).toBeInTheDocument();
  });

  it('shows a dash when there is no score or grade', () => {
    render(<ExposureBadge score={null} grade={null} />);
    expect(screen.getByText('—')).toBeInTheDocument();
  });
});

describe('ExposureCard', () => {
  it('renders nothing when exposure is absent or scoreless', () => {
    const { container } = render(<ExposureCard exposure={null} />);
    expect(container).toBeEmptyDOMElement();
    const { container: c2 } = render(<ExposureCard exposure={{ grade: 'B' }} />);
    expect(c2).toBeEmptyDOMElement();
  });

  it('renders the score, grade, and "no prior scan" when there is no baseline', () => {
    render(<ExposureCard exposure={{ score: 27, grade: 'B', previous_score: null, direction: 'flat', change: 0 }} />);
    expect(screen.getByText('27')).toBeInTheDocument();
    expect(screen.getByText('B')).toBeInTheDocument();
    expect(screen.getByText(/no prior scan/i)).toBeInTheDocument();
  });

  it('shows a rising exposure as worse (more exposure) when the score climbs', () => {
    render(<ExposureCard exposure={{ score: 40, grade: 'C', previous_score: 27, direction: 'up', change: 13 }} />);
    expect(screen.getByText(/more exposure/i)).toBeInTheDocument();
    expect(screen.getByText(/↑ 13/)).toBeInTheDocument();
  });
});
