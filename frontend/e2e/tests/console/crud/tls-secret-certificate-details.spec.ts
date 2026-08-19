import { test, expect } from '../../../fixtures';
import { DetailsPage } from '../../../pages/details-page';
import { generateTestName } from '../../../utils/test-name';
import { testCertificateMatrix } from './test-certificates';

const encodePEM = (pem: string): string => Buffer.from(pem).toString('base64');
const encodeValue = (value: string): string => Buffer.from(value).toString('base64');

const createTLSSecret = async (k8sClient, namespace: string, name: string, certificate: string) => {
  await k8sClient.createSecret(
    name,
    namespace,
    {
      'tls.crt': encodePEM(certificate),
      'tls.key': encodeValue('test-key'),
    },
    'kubernetes.io/tls',
  );
};

test.describe('TLS Secret certificate details', { tag: ['@admin'] }, () => {
  test.describe.configure({ mode: 'serial' });

  test('shows decoded certificate details for a TLS Secret', async ({ page, k8sClient, cleanup }) => {
    const testName = generateTestName();
    const namespace = `${testName}-tls-secret`;
    const secretName = `${testName}-tls`;
    const detailsPage = new DetailsPage(page);

    await k8sClient.createNamespace(namespace);
    await k8sClient.waitForNamespaceReady(namespace);
    cleanup.trackNamespace(namespace);
    await createTLSSecret(
      k8sClient,
      namespace,
      secretName,
      testCertificateMatrix.subjectRichCertificate,
    );

    await detailsPage.navigateToDetailsPage(`/k8s/ns/${namespace}/secrets/${secretName}`);
    await detailsPage.waitForPageLoad();
    await expect(page.getByTestId('tls-certificate-details')).toContainText('Value hidden');

    await page.getByTestId('reveal-certificate-values').click();

    await expect(page.getByTestId('tls-certificate-details')).toContainText(
      'CN=subject-rich.example.com',
    );
    await expect(page.getByTestId('tls-certificate-details')).toContainText('CountryUS');
    await expect(page.getByTestId('tls-certificate-details')).toContainText(
      'DNS: subject-rich.example.com',
    );
    await expect(page.getByTestId('tls-certificate-details')).toContainText(
      'Certificate authorityNo',
    );
  });

  test('shows each certificate in a TLS certificate chain', async ({ page, k8sClient, cleanup }) => {
    const testName = generateTestName();
    const namespace = `${testName}-tls-chain`;
    const secretName = `${testName}-chain`;
    const detailsPage = new DetailsPage(page);

    await k8sClient.createNamespace(namespace);
    await k8sClient.waitForNamespaceReady(namespace);
    cleanup.trackNamespace(namespace);
    await createTLSSecret(
      k8sClient,
      namespace,
      secretName,
      testCertificateMatrix.chainCertificate,
    );

    await detailsPage.navigateToDetailsPage(`/k8s/ns/${namespace}/secrets/${secretName}`);
    await detailsPage.waitForPageLoad();
    await page.getByTestId('reveal-certificate-values').click();

    await expect(page.getByRole('heading', { name: 'Certificate (1 of 2)' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Certificate (2 of 2)' })).toBeVisible();
    await expect(page.getByTestId('tls-certificate-details')).toContainText(
      'CN=leaf.chain.example.com',
    );
    await expect(page.getByTestId('tls-certificate-details')).toContainText(
      'CN=Console Test Intermediate CA',
    );
  });

  test('shows a standalone CA certificate as a certificate authority', async ({
    page,
    k8sClient,
    cleanup,
  }) => {
    const testName = generateTestName();
    const namespace = `${testName}-tls-ca`;
    const secretName = `${testName}-ca`;
    const detailsPage = new DetailsPage(page);

    await k8sClient.createNamespace(namespace);
    await k8sClient.waitForNamespaceReady(namespace);
    cleanup.trackNamespace(namespace);
    await createTLSSecret(
      k8sClient,
      namespace,
      secretName,
      testCertificateMatrix.standaloneCaCertificate,
    );

    await detailsPage.navigateToDetailsPage(`/k8s/ns/${namespace}/secrets/${secretName}`);
    await detailsPage.waitForPageLoad();
    await page.getByTestId('reveal-certificate-values').click();

    await expect(page.getByTestId('tls-certificate-details')).toContainText(
      'CN=Console Test Root CA',
    );
    await expect(page.getByTestId('tls-certificate-details')).toContainText('Certificate authorityYes');
  });

  test('shows a warning for a malformed TLS certificate', async ({ page, k8sClient, cleanup }) => {
    const testName = generateTestName();
    const namespace = `${testName}-tls-invalid`;
    const secretName = `${testName}-invalid`;
    const detailsPage = new DetailsPage(page);

    await k8sClient.createNamespace(namespace);
    await k8sClient.waitForNamespaceReady(namespace);
    cleanup.trackNamespace(namespace);
    await createTLSSecret(
      k8sClient,
      namespace,
      secretName,
      testCertificateMatrix.malformedCertificate,
    );

    await detailsPage.navigateToDetailsPage(`/k8s/ns/${namespace}/secrets/${secretName}`);
    await detailsPage.waitForPageLoad();
    await page.getByTestId('reveal-certificate-values').click();

    await expect(page.getByTestId('tls-certificate-decode-error')).toContainText(
      'Unable to decode certificate',
    );
  });
});
