/**
 * Key material and XML-DSig for the SAML IdP.
 *
 * A fresh self-signed certificate per mock instance, held in memory. No key
 * material lives in the repository, and nothing here is meant to be secure —
 * it exists so that a signature can be produced and then verified.
 */

import forge from 'node-forge';
import { SignedXml } from 'xml-crypto';

export interface KeyMaterial {
  privateKeyPem: string;
  certificatePem: string;
}

export function generateKeyMaterial(): KeyMaterial {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 24 * 3600 * 1000);
  const attrs = [{ name: 'commonName', value: 'mock-idp' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey),
    certificatePem: forge.pki.certificateToPem(cert),
  };
}

export function signXml(
  xml: string,
  key: KeyMaterial,
  opts: { referenceXPath?: string } = {},
): string {
  const sig = new SignedXml({
    privateKey: key.privateKeyPem,
    publicCert: key.certificatePem,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  });
  sig.addReference({
    xpath: opts.referenceXPath ?? "//*[local-name(.)='Assertion']",
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
  });
  sig.computeSignature(xml);
  return sig.getSignedXml();
}
