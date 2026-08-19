import { testCertificateMatrix } from '../test-certificates';
import { getDecodedCertificates } from '../tls-certificate-utils';

const encodePEM = (pem: string): string => Buffer.from(pem).toString('base64');

describe('tls-certificate-utils', () => {
  describe('getDecodedCertificates', () => {
    it('should decode subject, issuer, SANs, extensions, and RSA public key details', () => {
      const [certificate] = getDecodedCertificates(
        encodePEM(testCertificateMatrix.subjectRichCertificate),
      );

      expect(certificate.subject).toContain('CN=subject-rich.example.com');
      expect(certificate.issuer).toContain('CN=subject-rich.example.com');
      expect(certificate.subjectAttributes).toStrictEqual([
        { label: 'Common name', values: ['subject-rich.example.com'] },
        { label: 'Organization', values: ['OpenShift Console'] },
        { label: 'Organizational unit', values: ['TLS Test Team'] },
        { label: 'Country', values: ['US'] },
        { label: 'State or province', values: ['North Carolina'] },
        { label: 'Locality', values: ['Raleigh'] },
        { label: 'Email address', values: ['cert-admin@example.com'] },
        { label: 'Serial number', values: ['subject-serial-1'] },
        { label: 'Street address', values: ['100 Main St'] },
        { label: 'Postal code', values: ['27601'] },
      ]);
      expect(certificate.issuerAttributes).toStrictEqual(certificate.subjectAttributes);
      expect(certificate.subjectAlternativeNames).toStrictEqual([
        { type: 'DNS', value: 'subject-rich.example.com' },
        { type: 'DNS', value: 'service.namespace.svc' },
        { type: 'IP', value: '127.0.0.1' },
        { type: 'Email', value: 'cert-admin@example.com' },
        { type: 'URI', value: 'https://subject-rich.example.com' },
      ]);
      expect(certificate.isCertificateAuthority).toBe(false);
      expect(certificate.publicKey).toMatchObject({
        algorithm: 'rsaEncryption',
        exponent: '65537 (0x010001)',
        size: '2048 bit',
      });
      expect(certificate.publicKey.modulus).toContain(':');
      expect(certificate.extensions).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ critical: true, name: 'Basic constraints', value: 'CA:FALSE' }),
          expect.objectContaining({
            critical: true,
            name: 'Key usage',
            value: 'Digital Signature, Key Encipherment',
          }),
          expect.objectContaining({
            name: 'Extended key usage',
            value: 'Server authentication, Client authentication',
          }),
        ]),
      );
      expect(certificate.version).toBe('3 (0x2)');
      expect(certificate.signatureAlgorithm).toBe('sha256WithRSAEncryption');
      expect(certificate.signatureValue).toContain(':');
    });

    it('should decode a certificate chain in PEM order', () => {
      const certificates = getDecodedCertificates(
        encodePEM(testCertificateMatrix.chainCertificate),
      );

      expect(certificates).toHaveLength(2);
      expect(certificates[0].subject).toContain('CN=leaf.chain.example.com');
      expect(certificates[0].issuer).toContain('CN=Console Test Intermediate CA');
      expect(certificates[0].isCertificateAuthority).toBe(false);
      expect(certificates[1].subject).toContain('CN=Console Test Intermediate CA');
      expect(certificates[1].isCertificateAuthority).toBe(true);
    });

    it('should decode a non-RSA certificate without RSA modulus or exponent fields', () => {
      const [certificate] = getDecodedCertificates(
        encodePEM(testCertificateMatrix.ecdsaCertificate),
      );

      expect(certificate.subject).toContain('CN=ecdsa.example.com');
      expect(certificate.publicKey.algorithm).toBe('id-ecPublicKey');
      expect(certificate.publicKey.exponent).toBeUndefined();
      expect(certificate.publicKey.modulus).toBeUndefined();
      expect(certificate.signatureAlgorithm).toBe('ecdsa-with-SHA256');
    });

    it('should decode an Ed25519 certificate without RSA modulus or exponent fields', () => {
      const [certificate] = getDecodedCertificates(
        encodePEM(testCertificateMatrix.ed25519Certificate),
      );

      expect(certificate.subject).toContain('CN=ed25519.example.com');
      expect(certificate.publicKey.algorithm).toBe('Ed25519');
      expect(certificate.publicKey.exponent).toBeUndefined();
      expect(certificate.publicKey.modulus).toBeUndefined();
    });

    it('should decode a standalone CA certificate as a certificate authority', () => {
      const [certificate] = getDecodedCertificates(
        encodePEM(testCertificateMatrix.standaloneCaCertificate),
      );

      expect(certificate.subject).toContain('CN=Console Test Root CA');
      expect(certificate.isCertificateAuthority).toBe(true);
      expect(certificate.extensions).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ critical: true, name: 'Basic constraints', value: 'CA:TRUE' }),
          expect.objectContaining({
            critical: true,
            name: 'Key usage',
            value: 'Certificate Sign, CRL Sign',
          }),
          expect.objectContaining({ name: 'Subject key identifier' }),
        ]),
      );
    });

    it('should return an empty array when base64 content contains no PEM certificate block', () => {
      expect(getDecodedCertificates(encodePEM('not a certificate'))).toStrictEqual([]);
    });

    it('should throw when a PEM certificate block has malformed DER content', () => {
      expect(() =>
        getDecodedCertificates(encodePEM(testCertificateMatrix.malformedCertificate)),
      ).toThrow('Unable to decode certificate');
    });
  });
});
