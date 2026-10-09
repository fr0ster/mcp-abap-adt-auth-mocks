/**
 * Key material and XML-DSig for the SAML IdP.
 *
 * A fresh self-signed certificate per mock instance, held in memory. No key
 * material lives in the repository, and nothing here is meant to be secure —
 * it exists so that a signature can be produced and then verified.
 */

import { generateKeyPairSync } from 'node:crypto';
import { SignedXml } from 'xml-crypto';
import { certificateToPem, selfSignedCertificate } from './x509';

export interface KeyMaterial {
  privateKeyPem: string;
  certificatePem: string;
}

export function generateKeyMaterial(): KeyMaterial {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  const now = Date.now();
  const der = selfSignedCertificate({
    commonName: 'mock-idp',
    serial: Buffer.from([0x01]),
    notBefore: new Date(now - 60_000),
    notAfter: new Date(now + 24 * 3600 * 1000),
    publicKey,
    privateKey,
  });

  return {
    // PKCS#1 ("BEGIN RSA PRIVATE KEY"), the form this package has always
    // handed out.
    privateKeyPem: privateKey
      .export({ type: 'pkcs1', format: 'pem' })
      .toString(),
    certificatePem: certificateToPem(der),
  };
}

const DEFAULT_REFERENCE = "//*[local-name(.)='Assertion']";

/**
 * Where the SAML 2.0 assertion schema — and every real identity provider —
 * places the `Signature`: the second child, immediately after `Issuer`. Left
 * to its default, `computeSignature` appends the `Signature` under the
 * document root instead of under the element the `Reference` actually names,
 * which a structural verifier (node-saml among them) rejects outright even
 * though the cryptographic signature itself is correct — the parent of the
 * `Signature` no longer matches the node its own `Reference` points at.
 */
const SCHEMA_SIGNATURE_LOCATION = `${DEFAULT_REFERENCE}/*[local-name(.)='Issuer']`;

/**
 * Where to insert the `Signature`, in xml-crypto's own terms: an XPath to an
 * existing node, and whether the `Signature` goes before or after it, or
 * becomes its first or last child.
 */
export interface SignatureLocation {
  reference: string;
  action: 'append' | 'prepend' | 'before' | 'after';
}

export function signXml(
  xml: string,
  key: KeyMaterial,
  opts: { referenceXPath?: string; location?: SignatureLocation } = {},
): string {
  const referenceXPath = opts.referenceXPath ?? DEFAULT_REFERENCE;
  const sig = new SignedXml({
    privateKey: key.privateKeyPem,
    publicCert: key.certificatePem,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  });
  sig.addReference({
    xpath: referenceXPath,
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
  });
  // The default reference signs a SAML Assertion, so the Signature can go
  // exactly where the schema puts it — right after the Assertion's own
  // Issuer. A caller-supplied referenceXPath signs an arbitrary element that
  // is not guaranteed to have an Issuer child at all, so without an explicit
  // location it falls back to appending the Signature as that element's own
  // last child: still the referenced element's child, which is what
  // satisfies a structural verifier, just not schema-ordered. A caller that
  // knows the schema of what it signs passes `location` and gets the order
  // right.
  const location: SignatureLocation =
    opts.location ??
    (opts.referenceXPath === undefined
      ? { reference: SCHEMA_SIGNATURE_LOCATION, action: 'after' }
      : { reference: referenceXPath, action: 'append' });
  sig.computeSignature(xml, { location });
  return sig.getSignedXml();
}
