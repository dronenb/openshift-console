import type { FC } from 'react';
import { useMemo, useState } from 'react';
import {
  Alert,
  Button,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Title,
} from '@patternfly/react-core';
import { RhUiViewIcon, RhUiViewOffIcon } from '@patternfly/react-icons';
import { useTranslation } from 'react-i18next';
import { DASH } from '@console/shared/src/constants/ui';
import { CopyToClipboard } from '../utils/copy-to-clipboard';
import { SectionHeading } from '../utils/headings';
import {
  formatUTCDate,
  getDecodedCertificates,
  type CertificateExtension,
  type CertificateExtensionName,
  type CertificateNameAttributeField,
  type CertificateSubjectAlternativeName,
  type DecodedCertificate,
} from './tls-certificate-utils';

const CertificateDetailsItem: FC<CertificateDetailsItemProps> = ({ label, children }) => (
  <DescriptionListGroup>
    <DescriptionListTerm>{label}</DescriptionListTerm>
    <DescriptionListDescription>{children || DASH}</DescriptionListDescription>
  </DescriptionListGroup>
);

const CertificateDetailsChildItem: FC<CertificateDetailsItemProps> = ({ label, children }) => (
  <div
    className="pf-v6-u-mt-sm pf-v6-u-pl-md"
    style={{ borderLeft: '3px solid var(--pf-t--global--border--color--default)' }}
  >
    <span className="pf-v6-u-font-weight-bold pf-v6-u-mr-sm">{label}</span>
    <span>{children || DASH}</span>
  </div>
);

const CertificateDetailsMaskedData: FC = () => {
  const { t } = useTranslation('public');
  return (
    <>
      <span className="pf-v6-u-screen-reader">{t('Value hidden')}</span>
      <span aria-hidden="true">{DASH}</span>
    </>
  );
};

const CertificateSubjectAlternativeNames: FC<CertificateSubjectAlternativeNamesProps> = ({
  critical,
  names,
}) => {
  const { t } = useTranslation('public');
  const value = names.map((name) => `${name.type}: ${name.value}`).join(', ');

  return names.length ? (
    <>
      <div>{critical ? `${t('Critical')}: ${value}` : value}</div>
      {names.map((name) => (
        <CertificateDetailsChildItem label={name.type} key={`${name.type}-${name.value}`}>
          {name.value}
        </CertificateDetailsChildItem>
      ))}
    </>
  ) : (
    DASH
  );
};

const CertificateNameAttributeLabel: FC<CertificateNameAttributeLabelProps> = ({ label }) => {
  const { t } = useTranslation('public');

  switch (label) {
    case 'Common name':
      return <>{t('Common name')}</>;
    case 'Country':
      return <>{t('Country')}</>;
    case 'Email address':
      return <>{t('Email address')}</>;
    case 'Locality':
      return <>{t('Locality')}</>;
    case 'Organization':
      return <>{t('Organization')}</>;
    case 'Organizational unit':
      return <>{t('Organizational unit')}</>;
    case 'Postal code':
      return <>{t('Postal code')}</>;
    case 'Serial number':
      return <>{t('Serial number')}</>;
    case 'State or province':
      return <>{t('State or province')}</>;
    case 'Street address':
      return <>{t('Street address')}</>;
    default:
      return null;
  }
};

const CertificateDetailsRevealButton: FC<CertificateDetailsRevealButtonProps> = ({
  reveal,
  onClick,
}) => {
  const { t } = useTranslation('public');
  return (
    <Button
      type="button"
      onClick={onClick}
      variant="link"
      className="pf-m-link--align-right"
      data-test="reveal-certificate-values"
    >
      {reveal ? (
        <>
          <RhUiViewOffIcon className="co-icon-space-r" />
          {t('Hide values')}
        </>
      ) : (
        <>
          <RhUiViewIcon className="co-icon-space-r" />
          {t('Reveal values')}
        </>
      )}
    </Button>
  );
};

export const TLSCertificateData: FC<TLSCertificateDataProps> = ({ encodedCertificate }) => {
  const { t } = useTranslation('public');
  const [reveal, setReveal] = useState(false);
  const certificates = useMemo(() => {
    if (!reveal) {
      return [];
    }

    try {
      return getDecodedCertificates(encodedCertificate);
    } catch {
      return null;
    }
  }, [encodedCertificate, reveal]);

  const getCertificateHeading = (index: number): string => {
    const position = t('{{index}} of {{total}}', {
      index: index + 1,
      total: certificates?.length || 0,
    });

    return t('Certificate ({{position}})', { position });
  };

  const getExtensionValue = (extension?: CertificateExtension): string => {
    if (!extension) {
      return DASH;
    }

    return extension.critical ? `${t('Critical')}: ${extension.value}` : extension.value;
  };

  const getCertificateExtensionValue = (
    certificate: DecodedCertificate,
    name: CertificateExtensionName,
  ): CertificateExtension | undefined =>
    certificate.extensions.find((extension) => extension.name === name);

  return (
    <>
      <SectionHeading text={t('Certificate details')}>
        <CertificateDetailsRevealButton reveal={reveal} onClick={() => setReveal(!reveal)} />
      </SectionHeading>
      <div data-test="tls-certificate-details">
        {!reveal ? (
          <CertificateDetailsMaskedData />
        ) : certificates?.length ? (
          certificates.map((certificate, index) => (
            <div className="pf-v6-u-mb-lg" data-test="tls-certificate-data" key={certificate.id}>
              {certificates.length > 1 && (
                <Title headingLevel="h3" className="pf-v6-u-mb-md">
                  {getCertificateHeading(index)}
                </Title>
              )}
              <DescriptionList>
                <CertificateDetailsItem label={t('Subject')}>
                  {certificate.subject}
                  {certificate.subjectAttributes.map(({ label, values }) => (
                    <CertificateDetailsChildItem
                      label={<CertificateNameAttributeLabel label={label} />}
                      key={label}
                    >
                      {values.join(', ')}
                    </CertificateDetailsChildItem>
                  ))}
                </CertificateDetailsItem>
                <CertificateDetailsItem label={t('Issuer')}>
                  {certificate.issuer}
                  {certificate.issuerAttributes.map(({ label, values }) => (
                    <CertificateDetailsChildItem
                      label={<CertificateNameAttributeLabel label={label} />}
                      key={label}
                    >
                      {values.join(', ')}
                    </CertificateDetailsChildItem>
                  ))}
                </CertificateDetailsItem>
                <CertificateDetailsItem label={t('Valid from')}>
                  {formatUTCDate(certificate.notBefore)}
                </CertificateDetailsItem>
                <CertificateDetailsItem label={t('Valid until')}>
                  {formatUTCDate(certificate.notAfter)}
                </CertificateDetailsItem>
                <CertificateDetailsItem label={t('Public key algorithm')}>
                  {certificate.publicKey.algorithm}
                </CertificateDetailsItem>
                <CertificateDetailsItem label={t('Public key size')}>
                  {certificate.publicKey.size}
                </CertificateDetailsItem>
                <CertificateDetailsItem label={t('Serial number')}>
                  {`${certificate.serialNumber.decimal} (0x${certificate.serialNumber.hex})`}
                </CertificateDetailsItem>
                <CertificateDetailsItem label={t('Version')}>
                  {certificate.version}
                </CertificateDetailsItem>
                <CertificateDetailsItem label={t('Signature algorithm')}>
                  {certificate.signatureAlgorithm}
                </CertificateDetailsItem>
                {certificate.publicKey.modulus && (
                  <CertificateDetailsItem label={t('Modulus')}>
                    <CopyToClipboard
                      id={`tls-certificate-${certificate.serialNumber.hex}-modulus`}
                      value={certificate.publicKey.modulus}
                    />
                  </CertificateDetailsItem>
                )}
                {certificate.publicKey.exponent && (
                  <CertificateDetailsItem label={t('Exponent')}>
                    {certificate.publicKey.exponent}
                  </CertificateDetailsItem>
                )}
                <CertificateDetailsItem label={t('Signature value')}>
                  <CopyToClipboard
                    id={`tls-certificate-${certificate.serialNumber.hex}-signature`}
                    value={certificate.signatureValue}
                  />
                </CertificateDetailsItem>
              </DescriptionList>
              <Title headingLevel="h4" className="pf-v6-u-mt-lg pf-v6-u-mb-md">
                {t('Extensions')}
              </Title>
              <DescriptionList>
                {getCertificateExtensionValue(certificate, 'Subject alternative names') && (
                  <CertificateDetailsItem label={t('Subject alternative names')}>
                    <CertificateSubjectAlternativeNames
                      critical={
                        getCertificateExtensionValue(certificate, 'Subject alternative names')
                          ?.critical
                      }
                      names={certificate.subjectAlternativeNames}
                    />
                  </CertificateDetailsItem>
                )}
                {getCertificateExtensionValue(certificate, 'Key usage') && (
                  <CertificateDetailsItem label={t('Key usage')}>
                    {getExtensionValue(getCertificateExtensionValue(certificate, 'Key usage'))}
                  </CertificateDetailsItem>
                )}
                {getCertificateExtensionValue(certificate, 'Extended key usage') && (
                  <CertificateDetailsItem label={t('Extended key usage')}>
                    {getExtensionValue(
                      getCertificateExtensionValue(certificate, 'Extended key usage'),
                    )}
                  </CertificateDetailsItem>
                )}
                {getCertificateExtensionValue(certificate, 'Basic constraints') && (
                  <CertificateDetailsItem label={t('Basic constraints')}>
                    {getExtensionValue(
                      getCertificateExtensionValue(certificate, 'Basic constraints'),
                    )}
                    <CertificateDetailsChildItem label={t('Certificate authority')}>
                      {certificate.isCertificateAuthority ? t('Yes') : t('No')}
                    </CertificateDetailsChildItem>
                  </CertificateDetailsItem>
                )}
                {getCertificateExtensionValue(certificate, 'Subject key identifier') && (
                  <CertificateDetailsItem label={t('Subject key identifier')}>
                    {getExtensionValue(
                      getCertificateExtensionValue(certificate, 'Subject key identifier'),
                    )}
                  </CertificateDetailsItem>
                )}
                {getCertificateExtensionValue(certificate, 'Authority key identifier') && (
                  <CertificateDetailsItem label={t('Authority key identifier')}>
                    {getExtensionValue(
                      getCertificateExtensionValue(certificate, 'Authority key identifier'),
                    )}
                  </CertificateDetailsItem>
                )}
              </DescriptionList>
            </div>
          ))
        ) : (
          <Alert
            isInline
            variant="warning"
            title={t('Unable to decode certificate')}
            data-test="tls-certificate-decode-error"
          />
        )}
      </div>
    </>
  );
};

type CertificateDetailsItemProps = {
  children: React.ReactNode;
  label: React.ReactNode;
};

type CertificateNameAttributeLabelProps = {
  label: CertificateNameAttributeField['label'];
};

type CertificateDetailsRevealButtonProps = {
  onClick: () => void;
  reveal: boolean;
};

type CertificateSubjectAlternativeNamesProps = {
  critical?: boolean;
  names: CertificateSubjectAlternativeName[];
};

type TLSCertificateDataProps = {
  encodedCertificate: string;
};
