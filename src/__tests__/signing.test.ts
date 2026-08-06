import { describe, expect, it } from '@jest/globals';
import { DOMParser, type Node } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import { generateKeyMaterial, signXml } from '../signing';

const ASSERTION = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"><saml:Issuer>mock-idp</saml:Issuer></saml:Assertion>`;

describe('signing', () => {
  it('generates a usable key pair and certificate', () => {
    const key = generateKeyMaterial();
    expect(key.privateKeyPem).toContain('BEGIN');
    expect(key.certificatePem).toContain('BEGIN CERTIFICATE');
  });

  it('produces a signature that verifies against its own certificate', () => {
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION, key);
    const doc = new DOMParser().parseFromString(signed, 'text/xml');
    const signature = doc.getElementsByTagNameNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'Signature',
    )[0];

    const verifier = new SignedXml({ publicCert: key.certificatePem });
    verifier.loadSignature(signature as unknown as Node);
    expect(verifier.checkSignature(signed)).toBe(true);
  });

  it('fails verification when the content is altered after signing', () => {
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION, key).replace('mock-idp', 'other-idp');
    const doc = new DOMParser().parseFromString(signed, 'text/xml');
    const signature = doc.getElementsByTagNameNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'Signature',
    )[0];

    const verifier = new SignedXml({ publicCert: key.certificatePem });
    verifier.loadSignature(signature as unknown as Node);
    expect(verifier.checkSignature(signed)).toBe(false);
  });

  it('fails verification against a different certificate', () => {
    const key = generateKeyMaterial();
    const other = generateKeyMaterial();
    const signed = signXml(ASSERTION, key);
    const doc = new DOMParser().parseFromString(signed, 'text/xml');
    const signature = doc.getElementsByTagNameNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'Signature',
    )[0];

    const verifier = new SignedXml({ publicCert: other.certificatePem });
    verifier.loadSignature(signature as unknown as Node);
    // xml-crypto@6.1.2's synchronous checkSignature() only *returns* false
    // when a reference digest fails to validate (the "content altered"
    // case above). When the SignedInfo's RSA signature value itself does
    // not verify against the supplied certificate — as here, where the
    // certificate belongs to a different key pair entirely — it throws
    // rather than returning false. See node_modules/xml-crypto/lib/signed-xml.js,
    // the `else` branch after `signer.verifySignature(...)`.
    expect(() => verifier.checkSignature(signed)).toThrow(/invalid signature/);
  });

  // `referenceXPath` is part of signXml's public signature but none of the
  // cases above ever pass it, so a bug that silently ignored the option
  // (always signing the default Assertion match) would go unnoticed. This
  // proves the option actually narrows what gets signed: altering content
  // outside the referenced element leaves the signature valid; altering the
  // referenced element itself invalidates it.
  it('signs only the element selected by a custom referenceXPath', () => {
    const key = generateKeyMaterial();
    const doc = `<Root xmlns="urn:test" ID="_root"><A ID="_a">alpha</A><B ID="_b">beta</B></Root>`;
    const signed = signXml(doc, key, {
      referenceXPath: "//*[local-name(.)='B']",
    });

    const verify = (xml: string): boolean => {
      const parsed = new DOMParser().parseFromString(xml, 'text/xml');
      const signature = parsed.getElementsByTagNameNS(
        'http://www.w3.org/2000/09/xmldsig#',
        'Signature',
      )[0];
      const verifier = new SignedXml({ publicCert: key.certificatePem });
      verifier.loadSignature(signature as unknown as Node);
      return verifier.checkSignature(xml);
    };

    expect(verify(signed)).toBe(true);
    expect(verify(signed.replace('alpha', 'ALPHA-CHANGED'))).toBe(true);
    expect(verify(signed.replace('beta', 'BETA-CHANGED'))).toBe(false);
  });
});
