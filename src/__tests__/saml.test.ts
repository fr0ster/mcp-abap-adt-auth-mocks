import { deflateRawSync } from 'node:zlib';
import { describe, expect, it } from '@jest/globals';
import { DOMParser, type Node } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import { visit } from '../browser';
import { startMockSamlIdp } from '../saml';
import { startServer } from '../server';

function authnRequest(acsUrl: string, id = '_req1'): string {
  const xml =
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `ID="${id}" Version="2.0" AssertionConsumerServiceURL="${acsUrl}"/>`;
  return deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64');
}

/** An ACS that records what the browser posts to it. */
async function startAcs() {
  const received: Record<string, string>[] = [];
  const server = await startServer({
    'POST /callback': (req, res) => {
      received.push(req.body);
      res.end('ok');
    },
  });
  return { ...server, received };
}

describe('mock SAML IdP', () => {
  it('returns an auto-submitting form rather than posting to the ACS itself', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp();
    try {
      const url = `${idp.url}/sso?SAMLRequest=${encodeURIComponent(
        authnRequest(`${acs.url}/callback`),
      )}`;
      const page = await (await fetch(url)).text();
      expect(page).toMatch(/<form[^>]+method=["']post["']/i);
      expect(page).toContain(`${acs.url}/callback`);
      // Nothing reached the ACS: delivery is the browser's job.
      expect(acs.received).toHaveLength(0);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('delivers the assertion when a browser submits the form', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp();
    try {
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(authnRequest(`${acs.url}/callback`))}`,
      );
      expect(acs.received).toHaveLength(1);
      expect(acs.received[0].SAMLResponse).toBeTruthy();
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('carries RelayState from the query string through the form', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp();
    try {
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(
          authnRequest(`${acs.url}/callback`),
        )}&RelayState=${encodeURIComponent('rs-abc')}`,
      );
      expect(acs.received[0].RelayState).toBe('rs-abc');
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('signs the assertion by default and exposes its certificate', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp();
    try {
      expect(idp.certificatePem).toContain('BEGIN CERTIFICATE');
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(authnRequest(`${acs.url}/callback`))}`,
      );
      const xml = Buffer.from(acs.received[0].SAMLResponse, 'base64').toString(
        'utf8',
      );
      expect(xml).toContain('Signature');
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('omits the signature for the unsigned variant', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp({ variant: 'unsigned' });
    try {
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(authnRequest(`${acs.url}/callback`))}`,
      );
      const xml = Buffer.from(acs.received[0].SAMLResponse, 'base64').toString(
        'utf8',
      );
      expect(xml).not.toContain('Signature');
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('names a different ACS for the wrongDestination variant', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp({ variant: 'wrongDestination' });
    try {
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(authnRequest(`${acs.url}/callback`))}`,
      );
      const xml = Buffer.from(acs.received[0].SAMLResponse, 'base64').toString(
        'utf8',
      );
      const destination = /Destination="([^"]+)"/.exec(xml)?.[1];
      expect(destination).toBeTruthy();
      expect(destination).not.toBe(`${acs.url}/callback`);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('echoes InResponseTo by default and breaks it on demand', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp();
    try {
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(
          authnRequest(`${acs.url}/callback`, '_req42'),
        )}`,
      );
      let xml = Buffer.from(acs.received[0].SAMLResponse, 'base64').toString(
        'utf8',
      );
      expect(xml).toContain('InResponseTo="_req42"');

      idp.setVariant('wrongInResponseTo');
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(
          authnRequest(`${acs.url}/callback`, '_req42'),
        )}`,
      );
      xml = Buffer.from(acs.received[1].SAMLResponse, 'base64').toString(
        'utf8',
      );
      expect(xml).not.toContain('InResponseTo="_req42"');
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  // RelayState is opaque data the client chose, and an ACS URL routinely
  // carries a query string. If either is dropped into the form unescaped, the
  // value is corrupted or the markup is — and every test above would still be
  // green, because none of them uses a character that matters.
  it('carries reserved characters through the form unharmed', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp();
    const relayState = 'a&b"c<d>e\'f';
    try {
      const acsUrl = `${acs.url}/callback?tenant=one&flow=saml`;
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(authnRequest(acsUrl))}` +
          `&RelayState=${encodeURIComponent(relayState)}`,
      );
      expect(acs.received).toHaveLength(1);
      expect(acs.received[0].RelayState).toBe(relayState);
      // The response still decodes, so the SAMLResponse survived escaping too.
      const xml = Buffer.from(acs.received[0].SAMLResponse, 'base64').toString(
        'utf8',
      );
      expect(xml).toContain('Assertion');
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  // Empty and absent are different messages. `RelayState=` is a value the
  // client chose to send; omitting the parameter is not. Replace the
  // `=== undefined` check with a truthy one and every other case stays green.
  it('carries an empty RelayState, and omits the field when there was none', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp();
    try {
      const request = encodeURIComponent(authnRequest(`${acs.url}/callback`));

      await visit(`${idp.url}/sso?SAMLRequest=${request}&RelayState=`);
      expect(acs.received).toHaveLength(1);
      expect(acs.received[0].RelayState).toBe('');

      const without = await (
        await fetch(`${idp.url}/sso?SAMLRequest=${request}`)
      ).text();
      expect(without).not.toContain('name="RelayState"');
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  // Replay is a sequence: the same assertion, delivered twice. In isolation the
  // second delivery is valid, which is exactly why a verifier must remember.
  it('repeats a previous assertion ID on demand', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp();
    try {
      const url = `${idp.url}/sso?SAMLRequest=${encodeURIComponent(
        authnRequest(`${acs.url}/callback`),
      )}`;
      await visit(url);
      const firstId = idp.lastAssertionId();
      expect(firstId).toBeTruthy();

      idp.repeatLastAssertion();
      await visit(url);
      const secondXml = Buffer.from(
        acs.received[1].SAMLResponse,
        'base64',
      ).toString('utf8');
      expect(secondXml).toContain(`ID="${firstId}"`);
    } finally {
      await idp.close();
      await acs.close();
    }
  });
});

/**
 * Coverage for the rest of the variant table.
 *
 * The task-9 brief's own test file (above, copied verbatim) only exercises
 * unsigned, wrongDestination and wrongInResponseTo directly. The remaining
 * eight variants are rules this module performs too, so per the "strict by
 * default" constraint each gets a test that would fail if its one-field
 * change were dropped or if it started corrupting a second field.
 */
describe('mock SAML IdP — remaining variant-table entries', () => {
  async function deliveredXml(
    idp: { url: string },
    acsUrl: string,
    acs: { received: Record<string, string>[] },
    requestId = '_req1',
  ): Promise<string> {
    await visit(
      `${idp.url}/sso?SAMLRequest=${encodeURIComponent(authnRequest(acsUrl, requestId))}`,
    );
    const last = acs.received[acs.received.length - 1];
    return Buffer.from(last.SAMLResponse, 'base64').toString('utf8');
  }

  function signatureVerifier(xml: string, certificatePem: string): SignedXml {
    const doc = new DOMParser().parseFromString(xml, 'text/xml');
    const signature = doc.getElementsByTagNameNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'Signature',
    )[0];
    const verifier = new SignedXml({ publicCert: certificatePem });
    verifier.loadSignature(signature as unknown as Node);
    return verifier;
  }

  it('statusFailure sets StatusCode to Responder and leaves the rest correct', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp({ variant: 'statusFailure' });
    try {
      const acsUrl = `${acs.url}/callback`;
      const xml = await deliveredXml(idp, acsUrl, acs, '_req1');
      expect(xml).toContain(
        'StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"',
      );
      expect(xml).toContain(`Destination="${acsUrl}"`);
      expect(xml).toContain('InResponseTo="_req1"');
      expect(xml).toContain('Signature');
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('expired puts NotOnOrAfter in the past and leaves the rest correct', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp({ variant: 'expired' });
    try {
      const acsUrl = `${acs.url}/callback`;
      const xml = await deliveredXml(idp, acsUrl, acs);
      const notOnOrAfter = /NotOnOrAfter="([^"]+)"/.exec(xml)?.[1];
      expect(notOnOrAfter).toBeTruthy();
      expect(new Date(notOnOrAfter as string).getTime()).toBeLessThan(
        Date.now(),
      );
      expect(xml).toContain(
        'StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"',
      );
      expect(xml).toContain(`Destination="${acsUrl}"`);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('notYetValid puts NotBefore in the future and leaves the rest correct', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp({ variant: 'notYetValid' });
    try {
      const acsUrl = `${acs.url}/callback`;
      const xml = await deliveredXml(idp, acsUrl, acs);
      const notBefore = /NotBefore="([^"]+)"/.exec(xml)?.[1];
      expect(notBefore).toBeTruthy();
      expect(new Date(notBefore as string).getTime()).toBeGreaterThan(
        Date.now(),
      );
      // NotOnOrAfter is still in the future too — only NotBefore moved.
      const notOnOrAfter = /NotOnOrAfter="([^"]+)"/.exec(xml)?.[1];
      expect(new Date(notOnOrAfter as string).getTime()).toBeGreaterThan(
        Date.now(),
      );
      expect(xml).toContain(`Destination="${acsUrl}"`);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('wrongAudience replaces the Audience and leaves the rest correct', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp({ variant: 'wrongAudience' });
    try {
      const acsUrl = `${acs.url}/callback`;
      const xml = await deliveredXml(idp, acsUrl, acs, '_req1');
      expect(xml).toContain('<saml:Audience>urn:someone:else</saml:Audience>');
      expect(xml).toContain(`Destination="${acsUrl}"`);
      expect(xml).toContain('InResponseTo="_req1"');
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('wrongRecipient replaces Recipient but leaves Destination correct', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp({ variant: 'wrongRecipient' });
    try {
      const acsUrl = `${acs.url}/callback`;
      const xml = await deliveredXml(idp, acsUrl, acs);
      expect(xml).toContain('Recipient="http://127.0.0.1:1/other"');
      expect(xml).toContain(`Destination="${acsUrl}"`);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('wrongIssuer replaces the Issuer but leaves Destination and Recipient correct', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp({ variant: 'wrongIssuer' });
    try {
      const acsUrl = `${acs.url}/callback`;
      const xml = await deliveredXml(idp, acsUrl, acs);
      expect(xml).toContain('<saml:Issuer>urn:other:idp</saml:Issuer>');
      expect(xml).not.toContain('>mock-idp<');
      expect(xml).toContain(`Destination="${acsUrl}"`);
      expect(xml).toContain(`Recipient="${acsUrl}"`);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('wrongKey signs with an unrelated key pair, so the shipped certificate no longer verifies it', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp({ variant: 'wrongKey' });
    try {
      const acsUrl = `${acs.url}/callback`;
      const xml = await deliveredXml(idp, acsUrl, acs);
      expect(xml).toContain('Signature');
      const verifier = signatureVerifier(xml, idp.certificatePem);
      // Per xml-crypto@6.1.2: a signature made with a different key pair
      // entirely fails the RSA signature-value check itself, which throws
      // rather than returning false (see signing.test.ts).
      expect(() => verifier.checkSignature(xml)).toThrow(/invalid signature/);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('tamperedAfterSign signs correctly, then breaks the digest of signed content', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp({ variant: 'tamperedAfterSign' });
    try {
      const acsUrl = `${acs.url}/callback`;
      const xml = await deliveredXml(idp, acsUrl, acs);
      expect(xml).toContain('Signature');
      const verifier = signatureVerifier(xml, idp.certificatePem);
      // Signed with the real key, so the RSA signature value itself checks
      // out; the reference digest no longer matches the altered content,
      // which is the "content changed after signing" case — a plain false,
      // not a throw.
      expect(verifier.checkSignature(xml)).toBe(false);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('wrongDestination leaves Recipient pointing at the real ACS', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp({ variant: 'wrongDestination' });
    try {
      const acsUrl = `${acs.url}/callback`;
      const xml = await deliveredXml(idp, acsUrl, acs);
      expect(xml).toContain(`Recipient="${acsUrl}"`);
    } finally {
      await idp.close();
      await acs.close();
    }
  });
});
