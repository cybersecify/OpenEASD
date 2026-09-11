import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { FindingDetailModal } from './FindingDetailModal.jsx';

const base = {
  id: 1,
  severity: 'high',
  title: 'MTA-STS not configured',
  source: 'domain_security',
  check_type: 'email',
  status: 'open',
  target: 'example.com',
  description: 'No MTA-STS policy — TLS downgrade risk.',
  remediation: '1. Add DNS TXT record\n2. Host the policy file',
  extra: {},
  discovered_at: '2026-09-09T15:56:45Z',
};

describe('FindingDetailModal', () => {
  it('renders nothing when no finding is passed', () => {
    const { container } = render(<FindingDetailModal finding={null} onClose={() => {}} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('shows the title, severity, description and remediation', () => {
    render(<FindingDetailModal finding={base} onClose={() => {}} />);
    expect(screen.getByText('MTA-STS not configured')).toBeInTheDocument();
    expect(screen.getByText('high')).toBeInTheDocument();
    expect(screen.getByText(/No MTA-STS policy/)).toBeInTheDocument();
    expect(screen.getByText(/Add DNS TXT record/)).toBeInTheDocument();
  });

  it('surfaces CVE / CVSS / EPSS / KEV from extra', () => {
    const f = {
      ...base,
      title: 'OpenSSH vuln',
      extra: { cve_ids: ['CVE-2024-1234', 'CVE-2024-5678'], cvss_score: 9.8, epss_score: 0.42, kev: true },
    };
    render(<FindingDetailModal finding={f} onClose={() => {}} />);
    expect(screen.getByText('Vulnerability Intelligence')).toBeInTheDocument();
    expect(screen.getByText('CVE-2024-1234')).toBeInTheDocument();
    expect(screen.getByText('CVE-2024-5678')).toBeInTheDocument();
    expect(screen.getByText('9.8')).toBeInTheDocument();
    expect(screen.getByText('42.0%')).toBeInTheDocument();     // epss 0.42 → 42.0%
    expect(screen.getByText(/CISA KEV/)).toBeInTheDocument();  // label chip: "CISA KEV: yes"
  });

  it('omits the vulnerability block when extra is empty', () => {
    render(<FindingDetailModal finding={base} onClose={() => {}} />);
    expect(screen.queryByText('Vulnerability Intelligence')).not.toBeInTheDocument();
  });

  it('renders unknown extra keys as a generic key/value list', () => {
    const f = { ...base, extra: { banner: 'nginx/1.18.0', port: 8080 } };
    render(<FindingDetailModal finding={f} onClose={() => {}} />);
    expect(screen.getByText('banner')).toBeInTheDocument();
    expect(screen.getByText('nginx/1.18.0')).toBeInTheDocument();
  });

  it('calls onClose when the Close button is clicked', () => {
    const onClose = vi.fn();
    render(<FindingDetailModal finding={base} onClose={onClose} />);
    fireEvent.click(screen.getByText('Close'));
    expect(onClose).toHaveBeenCalled();
  });
});
