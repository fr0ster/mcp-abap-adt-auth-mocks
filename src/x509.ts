/**
 * A self-signed X.509 v3 certificate, built with node:crypto and a small DER
 * encoder — just enough ASN.1 for one certificate shape: an RSA key, a
 * subject and issuer of one CN, no extensions, signed with
 * sha256WithRSAEncryption. Plain code over bytes; nothing is parsed.
 */

import { type KeyObject, sign } from 'node:crypto';

const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_NULL = 0x05;
const TAG_UTF8_STRING = 0x0c;
const TAG_UTC_TIME = 0x17;
const TAG_GENERALIZED_TIME = 0x18;
const TAG_SEQUENCE = 0x30;
const TAG_SET = 0x31;
const TAG_VERSION = 0xa0; // [0] EXPLICIT, constructed

/** 1.2.840.113549.1.1.11 — sha256WithRSAEncryption, pre-encoded. */
const OID_SHA256_WITH_RSA = Buffer.from([
  0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
]);
/** 2.5.4.3 — id-at-commonName, pre-encoded. */
const OID_COMMON_NAME = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]);

/**
 * A DER length: short form below 128, else 0x80 | the number of length
 * bytes, followed by the length big-endian in as few bytes as it takes.
 */
export function encodeLength(length: number): Buffer {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new RangeError('a DER length is a non-negative integer');
  }
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  let rest = length;
  while (rest > 0) {
    bytes.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from([tag]),
    encodeLength(content.length),
    content,
  ]);
}

function sequence(...items: Buffer[]): Buffer {
  return tlv(TAG_SEQUENCE, Buffer.concat(items));
}

/** A positive INTEGER from its big-endian magnitude. */
function positiveInteger(magnitude: Buffer): Buffer {
  let start = 0;
  while (start < magnitude.length - 1 && magnitude[start] === 0) start++;
  const trimmed = magnitude.subarray(start);
  const first = trimmed[0] ?? 0;
  const content =
    trimmed.length === 0 || first & 0x80
      ? Buffer.concat([Buffer.from([0]), trimmed])
      : trimmed;
  return tlv(TAG_INTEGER, content);
}

function twoDigits(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

/**
 * RFC 5280 §4.1.2.5: UTCTime (YYMMDDHHMMSSZ) through 2049, GeneralizedTime
 * (YYYYMMDDHHMMSSZ) from 2050, both in UTC with whole seconds.
 */
function time(date: Date): Buffer {
  const year = date.getUTCFullYear();
  const rest =
    twoDigits(date.getUTCMonth() + 1) +
    twoDigits(date.getUTCDate()) +
    twoDigits(date.getUTCHours()) +
    twoDigits(date.getUTCMinutes()) +
    twoDigits(date.getUTCSeconds()) +
    'Z';
  if (year >= 1950 && year < 2050) {
    return tlv(
      TAG_UTC_TIME,
      Buffer.from(twoDigits(year % 100) + rest, 'ascii'),
    );
  }
  if (year < 0 || year > 9999) {
    throw new RangeError('a certificate time must fall in years 0000–9999');
  }
  const fullYear = String(year).padStart(4, '0');
  return tlv(TAG_GENERALIZED_TIME, Buffer.from(fullYear + rest, 'ascii'));
}

function commonNameOnly(commonName: string): Buffer {
  const attribute = sequence(
    OID_COMMON_NAME,
    tlv(TAG_UTF8_STRING, Buffer.from(commonName, 'utf8')),
  );
  return sequence(tlv(TAG_SET, attribute));
}

function sha256WithRsa(): Buffer {
  return sequence(OID_SHA256_WITH_RSA, tlv(TAG_NULL, Buffer.alloc(0)));
}

export interface SelfSignedCertificateOptions {
  commonName: string;
  /** The serial number's big-endian magnitude, e.g. `Buffer.from([1])`. */
  serial: Buffer;
  notBefore: Date;
  notAfter: Date;
  publicKey: KeyObject;
  privateKey: KeyObject;
}

/** The certificate's DER encoding. */
export function selfSignedCertificate(
  options: SelfSignedCertificateOptions,
): Buffer {
  const name = commonNameOnly(options.commonName);
  const spki = options.publicKey.export({ type: 'spki', format: 'der' });
  const tbs = sequence(
    tlv(TAG_VERSION, tlv(TAG_INTEGER, Buffer.from([0x02]))), // v3
    positiveInteger(options.serial),
    sha256WithRsa(),
    name, // issuer
    sequence(time(options.notBefore), time(options.notAfter)),
    name, // subject
    spki,
  );
  const signature = sign('sha256', tbs, options.privateKey);
  // A BIT STRING's first content byte is the count of unused bits: none.
  const signatureBits = tlv(
    TAG_BIT_STRING,
    Buffer.concat([Buffer.from([0]), signature]),
  );
  return sequence(tbs, sha256WithRsa(), signatureBits);
}

/** PEM armour for a DER certificate, 64 base64 characters a line. */
export function certificateToPem(der: Buffer): string {
  const base64 = der.toString('base64');
  const lines: string[] = [];
  for (let i = 0; i < base64.length; i += 64) {
    lines.push(base64.slice(i, i + 64));
  }
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}
