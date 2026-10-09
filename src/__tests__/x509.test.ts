import {
  createPrivateKey,
  createPublicKey,
  X509Certificate,
} from 'node:crypto';
import { describe, expect, it } from '@jest/globals';
import { generateKeyMaterial } from '../signing';
import { certificateToPem, encodeLength } from '../x509';

/** Reads a DER length at `offset` (the byte after the tag), plain code. */
function readLength(
  der: Buffer,
  offset: number,
): { length: number; next: number } {
  const first = der[offset] ?? 0;
  if (first < 0x80) return { length: first, next: offset + 1 };
  const count = first & 0x7f;
  let length = 0;
  for (let i = 1; i <= count; i++)
    length = length * 256 + (der[offset + i] ?? 0);
  return { length, next: offset + 1 + count };
}

function derOf(pem: string): Buffer {
  const body = pem
    .split('\n')
    .filter((line) => line.length > 0 && !line.startsWith('-----'))
    .join('');
  return Buffer.from(body, 'base64');
}

describe('encodeLength', () => {
  it.each([
    [0, [0x00]],
    [1, [0x01]],
    [127, [0x7f]],
    [128, [0x81, 0x80]],
    [200, [0x81, 0xc8]],
    [255, [0x81, 0xff]],
    [256, [0x82, 0x01, 0x00]],
    [1000, [0x82, 0x03, 0xe8]],
    [65535, [0x82, 0xff, 0xff]],
    [65536, [0x83, 0x01, 0x00, 0x00]],
  ])('encodes %i as %j', (length, bytes) => {
    expect([...encodeLength(length)]).toEqual(bytes);
  });

  it('refuses a negative or fractional length', () => {
    expect(() => encodeLength(-1)).toThrow(RangeError);
    expect(() => encodeLength(1.5)).toThrow(RangeError);
  });
});

describe('generateKeyMaterial certificate', () => {
  it('parses as an X.509 certificate with the specified fields', () => {
    const before = Date.now();
    const key = generateKeyMaterial();
    const after = Date.now();
    const cert = new X509Certificate(key.certificatePem);

    expect(cert.subject).toBe('CN=mock-idp');
    expect(cert.issuer).toBe('CN=mock-idp');
    expect(cert.serialNumber).toBe('01');

    // Whole seconds on the wire: the window is now-60 s .. now+24 h,
    // truncated to the second.
    const second = (ms: number): number => Math.floor(ms / 1000) * 1000;
    const notBefore = Date.parse(cert.validFrom);
    const notAfter = Date.parse(cert.validTo);
    expect(notBefore).toBeGreaterThanOrEqual(second(before - 60_000));
    expect(notBefore).toBeLessThanOrEqual(after - 60_000);
    expect(notAfter).toBeGreaterThanOrEqual(second(before + 24 * 3600 * 1000));
    expect(notAfter).toBeLessThanOrEqual(after + 24 * 3600 * 1000);
    expect(notAfter - notBefore).toBe(24 * 3600 * 1000 + 60_000);
  });

  it('is self-signed by its own key, and carries that key', () => {
    const key = generateKeyMaterial();
    const cert = new X509Certificate(key.certificatePem);
    const privateKey = createPrivateKey(key.privateKeyPem);
    const ownPublic = createPublicKey(privateKey);

    expect(cert.verify(ownPublic)).toBe(true);
    expect(cert.checkIssued(cert)).toBe(true);
    expect(
      cert.publicKey
        .export({ type: 'spki', format: 'der' })
        .equals(ownPublic.export({ type: 'spki', format: 'der' })),
    ).toBe(true);
    expect(cert.publicKey.asymmetricKeyDetails?.modulusLength).toBe(2048);
  });

  it('does not verify against another key', () => {
    const key = generateKeyMaterial();
    const other = generateKeyMaterial();
    const cert = new X509Certificate(key.certificatePem);
    expect(cert.verify(createPublicKey(other.privateKeyPem))).toBe(false);
  });

  it('keeps the private key in PKCS#1 PEM', () => {
    const key = generateKeyMaterial();
    expect(
      key.privateKeyPem.startsWith('-----BEGIN RSA PRIVATE KEY-----\n'),
    ).toBe(true);
  });

  it('encodes the long lengths of the Certificate and its TBSCertificate', () => {
    const key = generateKeyMaterial();
    const der = derOf(key.certificatePem);

    expect(der[0]).toBe(0x30);
    const outer = readLength(der, 1);
    expect(outer.length).toBeGreaterThan(255);
    expect(der[1]).toBe(0x82); // two length bytes
    expect(outer.next + outer.length).toBe(der.length);

    expect(der[outer.next]).toBe(0x30);
    const tbs = readLength(der, outer.next + 1);
    expect(tbs.length).toBeGreaterThan(255);
    expect(der[outer.next + 1]).toBe(0x82);
  });

  it('wraps PEM at 64 characters a line', () => {
    const pem = certificateToPem(Buffer.alloc(100, 7));
    const lines = pem.trimEnd().split('\n');
    expect(lines[0]).toBe('-----BEGIN CERTIFICATE-----');
    expect(lines[lines.length - 1]).toBe('-----END CERTIFICATE-----');
    for (const line of lines.slice(1, -2)) expect(line.length).toBe(64);
  });
});
