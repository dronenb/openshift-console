import * as asn1js from 'asn1js';
import { Base64 } from 'js-base64';
import { Certificate } from 'pkijs';
import type { AttributeTypeAndValue, RelativeDistinguishedNames } from 'pkijs';

export const TLS_CERTIFICATE_KEY = 'tls.crt';

const PEM_CERTIFICATE_REGEX = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
const BASIC_CONSTRAINTS_EXTENSION = '2.5.29.19';
const KEY_USAGE_EXTENSION = '2.5.29.15';
const EXTENDED_KEY_USAGE_EXTENSION = '2.5.29.37';
const SUBJECT_ALT_NAME_EXTENSION = '2.5.29.17';
const SUBJECT_KEY_IDENTIFIER_EXTENSION = '2.5.29.14';
const AUTHORITY_KEY_IDENTIFIER_EXTENSION = '2.5.29.35';

const certificateAttributeLabels: { [oid: string]: string } = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '1.2.840.113549.1.9.1': 'emailAddress',
  '2.5.4.5': 'serialNumber',
  '2.5.4.9': 'streetAddress',
  '2.5.4.17': 'postalCode',
};

const certificateNameAttributeFields: CertificateNameAttributeField[] = [
  { label: 'Common name', oid: '2.5.4.3' },
  { label: 'Organization', oid: '2.5.4.10' },
  { label: 'Organizational unit', oid: '2.5.4.11' },
  { label: 'Country', oid: '2.5.4.6' },
  { label: 'State or province', oid: '2.5.4.8' },
  { label: 'Locality', oid: '2.5.4.7' },
  { label: 'Email address', oid: '1.2.840.113549.1.9.1' },
  { label: 'Serial number', oid: '2.5.4.5' },
  { label: 'Street address', oid: '2.5.4.9' },
  { label: 'Postal code', oid: '2.5.4.17' },
];

const extendedKeyUsageLabels: { [oid: string]: string } = {
  '1.3.6.1.5.5.7.3.1': 'Server authentication',
  '1.3.6.1.5.5.7.3.2': 'Client authentication',
  '1.3.6.1.5.5.7.3.3': 'Code signing',
  '1.3.6.1.5.5.7.3.4': 'Email protection',
  '1.3.6.1.5.5.7.3.8': 'Time stamping',
  '1.3.6.1.5.5.7.3.9': 'OCSP signing',
};

const keyUsageLabels = [
  'Digital Signature',
  'Non Repudiation',
  'Key Encipherment',
  'Data Encipherment',
  'Key Agreement',
  'Certificate Sign',
  'CRL Sign',
  'Encipher Only',
  'Decipher Only',
];

const algorithmLabels: { [oid: string]: string } = {
  '1.2.840.10045.2.1': 'id-ecPublicKey',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.2.840.113549.1.1.1': 'rsaEncryption',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.3.101.112': 'Ed25519',
};

const dateMonthLabels = [
  'Jan',
  'Feb',
  'Mar',
  'Apr',
  'May',
  'Jun',
  'Jul',
  'Aug',
  'Sep',
  'Oct',
  'Nov',
  'Dec',
];

const getCertificateAttributeValue = (attribute: AttributeTypeAndValue): string =>
  attribute.value?.valueBlock?.value ?? attribute.value?.valueBlock?.valueHexView?.toString() ?? '';

const getCertificateName = (name: RelativeDistinguishedNames): string =>
  name.typesAndValues
    .map((attribute) => {
      const label = certificateAttributeLabels[attribute.type] || attribute.type;
      const value = getCertificateAttributeValue(attribute);
      return value ? `${label}=${value}` : null;
    })
    .filter(Boolean)
    .join(', ');

const getCertificateAttributeValues = (name: RelativeDistinguishedNames, oid: string): string[] =>
  name.typesAndValues
    .filter((attribute) => attribute.type === oid)
    .map(getCertificateAttributeValue)
    .filter(Boolean);

const getCertificateNameAttributeFields = (
  name: RelativeDistinguishedNames,
): CertificateNameAttribute[] =>
  certificateNameAttributeFields
    .map(({ label, oid }) => ({ label, values: getCertificateAttributeValues(name, oid) }))
    .filter(({ values }) => values.length);

const getCertificateExtension = (certificate: Certificate, oid: string) =>
  certificate.extensions?.find((extension) => extension.extnID === oid);

const getAlgorithmLabel = (oid: string): string => algorithmLabels[oid] || oid;

export const formatUTCDate = (date: Date): string => {
  const day = date.getUTCDate().toString().padStart(2, ' ');
  const hours = date.getUTCHours().toString().padStart(2, '0');
  const minutes = date.getUTCMinutes().toString().padStart(2, '0');
  const seconds = date.getUTCSeconds().toString().padStart(2, '0');

  return `${dateMonthLabels[date.getUTCMonth()]} ${day} ${hours}:${minutes}:${seconds} ${date.getUTCFullYear()} GMT`;
};

const getHexView = (value): string => {
  const valueHexView = value?.valueBlock?.valueHexView;
  if (valueHexView) {
    return Array.from(valueHexView as Uint8Array)
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');
  }

  const { valueHex } = value?.valueBlock || {};
  return typeof valueHex === 'string' ? valueHex : '';
};

const formatColonHex = (hex: string): string => hex.match(/.{1,2}/g)?.join(':') || '';

const formatIndentedColonHex = (hex: string): string => {
  const colonHex = formatColonHex(hex);
  const lineLength = 45;
  const lines = [];

  for (let index = 0; index < colonHex.length; index += lineLength) {
    lines.push(colonHex.slice(index, index + lineLength));
  }

  return lines.join('\n');
};

const getIntegerHex = (value): string => getHexView(value).replace(/^00/, '') || '0';

const getSerialNumber = (certificate: Certificate): CertificateSerialNumber => {
  const hex = getIntegerHex(certificate.serialNumber);
  const decimal = BigInt(`0x${hex}`).toString(10);

  return { decimal, hex };
};

const getBitStringUsages = (valueBlock): string[] => {
  const { valueHexView, unusedBits = 0 } = valueBlock;
  if (!valueHexView?.length) {
    return [];
  }

  return keyUsageLabels.filter((_label, index) => {
    const byteIndex = Math.floor(index / 8);
    const bitIndex = 7 - (index % 8);
    const isUnusedBit = byteIndex === valueHexView.length - 1 && bitIndex < unusedBits;
    return !isUnusedBit && Math.floor(valueHexView[byteIndex] / 2 ** bitIndex) % 2 === 1;
  });
};

const getExtendedKeyUsages = (certificate: Certificate): string[] => {
  const extendedKeyUsage = getCertificateExtension(
    certificate,
    EXTENDED_KEY_USAGE_EXTENSION,
  )?.parsedValue;
  const usages = extendedKeyUsage?.keyPurposes || [];

  return usages.map((usage) => extendedKeyUsageLabels[usage] || usage);
};

const formatIPAddress = (value): string => {
  const bytes: number[] = Array.from(value?.valueBlock?.valueHexView || []);

  if (bytes.length === 4) {
    return bytes.join('.');
  }

  if (bytes.length === 16) {
    return bytes
      .reduce<string[]>((groups, byte, index) => {
        if (index % 2 === 0) {
          groups.push(`${byte.toString(16).padStart(2, '0')}`);
        } else {
          groups[groups.length - 1] += byte.toString(16).padStart(2, '0');
        }
        return groups;
      }, [])
      .join(':');
  }

  return value?.toString?.() || '';
};

const getGeneralNameValue = (generalName): CertificateSubjectAlternativeName => {
  switch (generalName.type) {
    case 1:
      return { type: 'Email', value: generalName.value };
    case 2:
      return { type: 'DNS', value: generalName.value };
    case 6:
      return { type: 'URI', value: generalName.value };
    case 7:
      return { type: 'IP', value: formatIPAddress(generalName.value) };
    default:
      return { type: generalName.type.toString(), value: generalName.value };
  }
};

const getSubjectAlternativeNames = (
  certificate: Certificate,
): CertificateSubjectAlternativeName[] => {
  const subjectAltName = getCertificateExtension(
    certificate,
    SUBJECT_ALT_NAME_EXTENSION,
  )?.parsedValue;
  const names = subjectAltName?.altNames || [];

  return names.map(getGeneralNameValue).filter(({ value }) => !!value);
};

const getBasicConstraintsValue = (certificate: Certificate): CertificateExtensionValue => {
  const extension = getCertificateExtension(certificate, BASIC_CONSTRAINTS_EXTENSION);
  return extension
    ? { critical: extension.critical, value: `CA:${extension.parsedValue?.cA ? 'TRUE' : 'FALSE'}` }
    : null;
};

const isCertificateAuthority = (certificate: Certificate): boolean =>
  !!getCertificateExtension(certificate, BASIC_CONSTRAINTS_EXTENSION)?.parsedValue?.cA;

const getKeyUsageValue = (certificate: Certificate): CertificateExtensionValue => {
  const extension = getCertificateExtension(certificate, KEY_USAGE_EXTENSION);
  if (!extension) {
    return null;
  }

  const usages = extension.parsedValue?.valueBlock
    ? getBitStringUsages(extension.parsedValue.valueBlock)
    : [];

  return { critical: extension.critical, value: usages.join(', ') || '-' };
};

const getExtendedKeyUsageValue = (certificate: Certificate): CertificateExtensionValue => {
  const extension = getCertificateExtension(certificate, EXTENDED_KEY_USAGE_EXTENSION);
  if (!extension) {
    return null;
  }

  return {
    critical: extension.critical,
    value: getExtendedKeyUsages(certificate).join(', ') || '-',
  };
};

const getSubjectAlternativeNameValue = (certificate: Certificate): CertificateExtensionValue => {
  const extension = getCertificateExtension(certificate, SUBJECT_ALT_NAME_EXTENSION);
  if (!extension) {
    return null;
  }

  return {
    critical: extension.critical,
    value:
      getSubjectAlternativeNames(certificate)
        .map((name) => `${name.type}: ${name.value}`)
        .join(', ') || '-',
  };
};

const getSubjectKeyIdentifierValue = (certificate: Certificate): CertificateExtensionValue => {
  const extension = getCertificateExtension(certificate, SUBJECT_KEY_IDENTIFIER_EXTENSION);
  const identifier = formatColonHex(getHexView(extension?.parsedValue));

  return extension ? { critical: extension.critical, value: identifier || '-' } : null;
};

const getAuthorityKeyIdentifierValue = (certificate: Certificate): CertificateExtensionValue => {
  const extension = getCertificateExtension(certificate, AUTHORITY_KEY_IDENTIFIER_EXTENSION);
  const identifier = formatColonHex(getHexView(extension?.parsedValue?.keyIdentifier));

  return extension ? { critical: extension.critical, value: identifier || '-' } : null;
};

const getCertificateExtensions = (certificate: Certificate): CertificateExtension[] =>
  [
    { name: 'Key usage' as const, details: getKeyUsageValue(certificate) },
    { name: 'Basic constraints' as const, details: getBasicConstraintsValue(certificate) },
    {
      name: 'Subject alternative names' as const,
      details: getSubjectAlternativeNameValue(certificate),
    },
    { name: 'Extended key usage' as const, details: getExtendedKeyUsageValue(certificate) },
    { name: 'Subject key identifier' as const, details: getSubjectKeyIdentifierValue(certificate) },
    {
      name: 'Authority key identifier' as const,
      details: getAuthorityKeyIdentifierValue(certificate),
    },
  ]
    .filter((extension): extension is CertificateExtensionSource => !!extension.details)
    .map(({ name, details }) => ({ name, ...details }));

const getRSAPublicKey = (certificate: Certificate): RSAPublicKey | null => {
  const publicKey = certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.value?.[0];
  const modulus = publicKey?.valueBlock?.value?.[0];
  const exponent = publicKey?.valueBlock?.value?.[1];
  if (!publicKey || !modulus || !exponent) {
    return null;
  }

  const modulusHex = getIntegerHex(modulus);
  const exponentHex = getIntegerHex(exponent);
  const exponentDecimal = BigInt(`0x${exponentHex}`).toString(10);

  return {
    exponent: `${exponentDecimal} (0x${exponentHex})`,
    modulus: formatIndentedColonHex(getHexView(modulus)),
    size: `${modulusHex.length * 4} bit`,
  };
};

const getPublicKey = (certificate: Certificate): CertificatePublicKey => {
  const algorithm = getAlgorithmLabel(certificate.subjectPublicKeyInfo.algorithm.algorithmId);
  const rsaPublicKey = algorithm === 'rsaEncryption' ? getRSAPublicKey(certificate) : null;
  const publicKeySize = getHexView(certificate.subjectPublicKeyInfo.subjectPublicKey).length * 4;

  return {
    algorithm,
    exponent: rsaPublicKey?.exponent,
    modulus: rsaPublicKey?.modulus,
    size: rsaPublicKey?.size || `${publicKeySize} bit`,
  };
};

export const getDecodedCertificates = (encodedCertificate: string): DecodedCertificate[] => {
  const pem = Base64.decode(encodedCertificate);
  const matches = pem.match(PEM_CERTIFICATE_REGEX) || [];

  return matches.map((certificatePem) => {
    const certificateBytes = Base64.toUint8Array(
      certificatePem
        .replace('-----BEGIN CERTIFICATE-----', '')
        .replace('-----END CERTIFICATE-----', '')
        .replace(/\s/g, ''),
    );
    const certificateDer = certificateBytes.buffer.slice(
      certificateBytes.byteOffset,
      certificateBytes.byteOffset + certificateBytes.byteLength,
    ) as ArrayBuffer;
    const asn1 = asn1js.fromBER(certificateDer);

    if (asn1.offset === -1) {
      throw new Error('Unable to decode certificate');
    }

    const certificate = new Certificate({ schema: asn1.result });
    const serialNumber = getSerialNumber(certificate);
    const signatureAlgorithm = getAlgorithmLabel(certificate.signatureAlgorithm.algorithmId);

    return {
      extensions: getCertificateExtensions(certificate),
      id: `${serialNumber.hex}-${getCertificateName(certificate.subject)}-${certificate.notBefore.value.toISOString()}`,
      isCertificateAuthority: isCertificateAuthority(certificate),
      issuer: getCertificateName(certificate.issuer),
      issuerAttributes: getCertificateNameAttributeFields(certificate.issuer),
      notAfter: certificate.notAfter.value,
      notBefore: certificate.notBefore.value,
      publicKey: getPublicKey(certificate),
      serialNumber,
      signatureAlgorithm,
      signatureValue: formatIndentedColonHex(getHexView(certificate.signatureValue)),
      subject: getCertificateName(certificate.subject),
      subjectAttributes: getCertificateNameAttributeFields(certificate.subject),
      subjectAlternativeNames: getSubjectAlternativeNames(certificate),
      version: `${certificate.version + 1} (0x${certificate.version.toString(16)})`,
    };
  });
};

export type DecodedCertificate = {
  extensions: CertificateExtension[];
  id: string;
  isCertificateAuthority: boolean;
  issuer: string;
  issuerAttributes: CertificateNameAttribute[];
  notAfter: Date;
  notBefore: Date;
  publicKey: CertificatePublicKey;
  serialNumber: CertificateSerialNumber;
  signatureAlgorithm: string;
  signatureValue: string;
  subject: string;
  subjectAttributes: CertificateNameAttribute[];
  subjectAlternativeNames: CertificateSubjectAlternativeName[];
  version: string;
};

export type CertificateNameAttributeField = {
  label:
    | 'Common name'
    | 'Country'
    | 'Email address'
    | 'Locality'
    | 'Organization'
    | 'Organizational unit'
    | 'Postal code'
    | 'Serial number'
    | 'State or province'
    | 'Street address';
  oid: string;
};

export type CertificateNameAttribute = {
  label: CertificateNameAttributeField['label'];
  values: string[];
};

export type CertificateSubjectAlternativeName = {
  type: string;
  value: string;
};

export type CertificateSerialNumber = {
  decimal: string;
  hex: string;
};

export type CertificatePublicKey = {
  algorithm: string;
  exponent?: string;
  modulus?: string;
  size: string;
};

type RSAPublicKey = {
  exponent: string;
  modulus: string;
  size: string;
};

export type CertificateExtensionName =
  | 'Key usage'
  | 'Basic constraints'
  | 'Subject alternative names'
  | 'Extended key usage'
  | 'Subject key identifier'
  | 'Authority key identifier';

type CertificateExtensionValue = {
  critical?: boolean;
  value: string;
} | null;

export type CertificateExtension = {
  critical?: boolean;
  name: CertificateExtensionName;
  value: string;
};

type CertificateExtensionSource = {
  details: Exclude<CertificateExtensionValue, null>;
  name: CertificateExtensionName;
};
