import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { TLSCertificateData } from '../tls-certificate-data';
import { getDecodedCertificates } from '../tls-certificate-utils';

jest.mock('../tls-certificate-utils', () => ({
  formatUTCDate: jest.fn((date: Date) => date.toISOString()),
  getDecodedCertificates: jest.fn(),
}));

jest.mock('../../utils/copy-to-clipboard', () => ({
  CopyToClipboard: jest.fn(({ value }) => value),
}));

const certificate = {
  extensions: [
    { critical: true, name: 'Subject alternative names' as const, value: 'DNS: app.example.com' },
    { critical: true, name: 'Key usage' as const, value: 'Digital Signature' },
    { name: 'Extended key usage' as const, value: 'Server authentication' },
    { critical: true, name: 'Basic constraints' as const, value: 'CA:FALSE' },
    { name: 'Subject key identifier' as const, value: 'aa:bb' },
    { name: 'Authority key identifier' as const, value: 'cc:dd' },
  ],
  id: 'leaf-cert',
  isCertificateAuthority: false,
  issuer: 'CN=Test Issuer, O=OpenShift Console',
  issuerAttributes: [
    { label: 'Common name' as const, values: ['Test Issuer'] },
    { label: 'Organization' as const, values: ['OpenShift Console'] },
  ],
  notAfter: new Date('2027-01-01T00:00:00Z'),
  notBefore: new Date('2026-01-01T00:00:00Z'),
  publicKey: {
    algorithm: 'rsaEncryption',
    exponent: '65537 (0x010001)',
    modulus: 'aa:bb:cc',
    size: '2048 bit',
  },
  serialNumber: { decimal: '123', hex: '7b' },
  signatureAlgorithm: 'sha256WithRSAEncryption',
  signatureValue: 'dd:ee:ff',
  subject: 'CN=app.example.com, O=OpenShift Console',
  subjectAlternativeNames: [{ type: 'DNS', value: 'app.example.com' }],
  subjectAttributes: [
    { label: 'Common name' as const, values: ['app.example.com'] },
    { label: 'Organization' as const, values: ['OpenShift Console'] },
  ],
  version: '3 (0x2)',
};

describe('TLSCertificateData', () => {
  beforeEach(() => {
    (getDecodedCertificates as jest.Mock).mockReturnValue([certificate]);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should hide decoded certificate values by default', () => {
    render(<TLSCertificateData encodedCertificate="encoded-cert" />);

    expect(screen.getByRole('heading', { name: /Certificate details/ })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Reveal values' })).toBeVisible();
    expect(screen.getByText('Value hidden')).toBeInTheDocument();
    expect(screen.queryByText('CN=app.example.com, O=OpenShift Console')).not.toBeInTheDocument();
    expect(getDecodedCertificates).not.toHaveBeenCalled();
  });

  it('should reveal decoded certificate values when requested', async () => {
    const user = userEvent.setup();
    render(<TLSCertificateData encodedCertificate="encoded-cert" />);

    await user.click(screen.getByRole('button', { name: 'Reveal values' }));

    expect(getDecodedCertificates).toHaveBeenCalledWith('encoded-cert');
    expect(screen.getByText('CN=app.example.com, O=OpenShift Console')).toBeVisible();
    expect(screen.getByText('CN=Test Issuer, O=OpenShift Console')).toBeVisible();
    expect(screen.getByText('rsaEncryption')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Hide values' })).toBeVisible();
  });

  it('should render subject and issuer decoded child fields', async () => {
    const user = userEvent.setup();
    render(<TLSCertificateData encodedCertificate="encoded-cert" />);

    await user.click(screen.getByRole('button', { name: 'Reveal values' }));

    const details = screen.getByTestId('tls-certificate-details');
    expect(within(details).getAllByText('Common name')).toHaveLength(2);
    expect(within(details).getAllByText('app.example.com')).toHaveLength(2);
    expect(within(details).getByText('Test Issuer')).toBeVisible();
  });

  it('should render extension values and nested derived fields', async () => {
    const user = userEvent.setup();
    render(<TLSCertificateData encodedCertificate="encoded-cert" />);

    await user.click(screen.getByRole('button', { name: 'Reveal values' }));

    expect(screen.getByRole('heading', { name: 'Extensions' })).toBeVisible();
    expect(screen.getByText('Critical: DNS: app.example.com')).toBeVisible();
    expect(screen.getByText('Critical: CA:FALSE')).toBeVisible();
    expect(screen.getByText('Certificate authority')).toBeVisible();
    expect(screen.getByText('No')).toBeVisible();
  });

  it('should render headings for multiple certificates', async () => {
    const user = userEvent.setup();
    (getDecodedCertificates as jest.Mock).mockReturnValue([
      certificate,
      { ...certificate, id: 'issuer-cert', subject: 'CN=issuer.example.com' },
    ]);
    render(<TLSCertificateData encodedCertificate="encoded-chain" />);

    await user.click(screen.getByRole('button', { name: 'Reveal values' }));

    expect(screen.getByRole('heading', { name: 'Certificate (1 of 2)' })).toBeVisible();
    expect(screen.getByRole('heading', { name: 'Certificate (2 of 2)' })).toBeVisible();
  });

  it('should show a decode warning when parsing fails', async () => {
    const user = userEvent.setup();
    (getDecodedCertificates as jest.Mock).mockImplementation(() => {
      throw new Error('Unable to decode certificate');
    });
    render(<TLSCertificateData encodedCertificate="bad-cert" />);

    await user.click(screen.getByRole('button', { name: 'Reveal values' }));

    expect(screen.getByText('Unable to decode certificate')).toBeVisible();
  });
});
