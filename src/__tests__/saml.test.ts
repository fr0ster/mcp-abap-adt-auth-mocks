import { deflateRawSync } from 'node:zlib';
import { describe, expect, it } from '@jest/globals';
import { DOMParser, type Node } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import { visit } from '../browser';
import { startMockSamlIdp } from '../saml';
import { startServer } from '../server';

/** Escapes a value for an XML attribute delimited by double quotes. */
function escapeXmlAttribute(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function authnRequest(acsUrl: string, id = '_req1'): string {
  const xml =
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `ID="${id}" Version="2.0" IssueInstant="${new Date().toISOString()}" ` +
    `AssertionConsumerServiceURL="${escapeXmlAttribute(acsUrl)}"/>`;
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
    const idp = await startMockSamlIdp({ acsUrls: [`${acs.url}/callback`] });
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
    const idp = await startMockSamlIdp({ acsUrls: [`${acs.url}/callback`] });
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
    const idp = await startMockSamlIdp({ acsUrls: [`${acs.url}/callback`] });
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
    const idp = await startMockSamlIdp({ acsUrls: [`${acs.url}/callback`] });
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
    const idp = await startMockSamlIdp({
      variant: 'unsigned',
      acsUrls: [`${acs.url}/callback`],
    });
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
    const idp = await startMockSamlIdp({
      variant: 'wrongDestination',
      acsUrls: [`${acs.url}/callback`],
    });
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
    const idp = await startMockSamlIdp({ acsUrls: [`${acs.url}/callback`] });
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
    const acsUrl = `${acs.url}/callback?tenant=one&flow=saml`;
    const idp = await startMockSamlIdp({ acsUrls: [acsUrl] });
    const relayState = 'a&b"c<d>e\'f';
    try {
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(authnRequest(acsUrl))}` +
          `&RelayState=${encodeURIComponent(relayState)}`,
      );
      expect(acs.received).toHaveLength(1);
      expect(acs.received[0].RelayState).toBe(relayState);
      // The POST actually landed with the query string intact — routing
      // matches on pathname alone, so this is the only thing here that would
      // notice the query string being mangled on the way through the form.
      expect(acs.requests[acs.requests.length - 1].query).toEqual({
        tenant: 'one',
        flow: 'saml',
      });
      // The response still decodes, so the SAMLResponse survived escaping too.
      const xml = Buffer.from(acs.received[0].SAMLResponse, 'base64').toString(
        'utf8',
      );
      expect(xml).toContain('Assertion');
      // Destination and Recipient are the ACS URL read back from the
      // AuthnRequest; a decoding mistake there corrupts both.
      const doc = new DOMParser().parseFromString(xml, 'text/xml');
      const destination = doc.documentElement?.getAttribute('Destination');
      expect(destination).toBe(acsUrl);
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
    const idp = await startMockSamlIdp({ acsUrls: [`${acs.url}/callback`] });
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
    const idp = await startMockSamlIdp({ acsUrls: [`${acs.url}/callback`] });
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

      // One-shot: repeatLastAssertion() was not called again, so a third
      // delivery must mint a fresh ID rather than repeating firstId forever.
      await visit(url);
      const thirdId = idp.lastAssertionId();
      expect(thirdId).toBeTruthy();
      expect(thirdId).not.toBe(firstId);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('refuses a request with no SAMLRequest parameter', async () => {
    const idp = await startMockSamlIdp();
    try {
      const res = await fetch(`${idp.url}/sso`);
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(/SAMLRequest/);
    } finally {
      await idp.close();
    }
  });

  it('refuses an AuthnRequest with no AssertionConsumerServiceURL', async () => {
    const idp = await startMockSamlIdp();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" IssueInstant="${new Date().toISOString()}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      // Exact fragment, not the bare `/AssertionConsumerServiceURL/` token:
      // the no-registration and not-registered refusals below both name
      // AssertionConsumerServiceURL too, so a bare token match stays green
      // even after this specific check is deleted.
      expect(await res.text()).toMatch(/missing AssertionConsumerServiceURL/);
    } finally {
      await idp.close();
    }
  });

  // The regex this replaced never rejected malformed XML — it simply found no
  // match and fell through to the "missing AssertionConsumerServiceURL"
  // refusal. A parser distinguishes the two failures, and a caller debugging
  // a broken AuthnRequest deserves to be told which one happened.
  it('refuses a SAMLRequest that does not decode to XML at all', async () => {
    const idp = await startMockSamlIdp();
    try {
      const encoded = deflateRawSync(
        Buffer.from('not xml at all', 'utf8'),
      ).toString('base64');
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(/did not parse as XML/);
    } finally {
      await idp.close();
    }
  });

  // The same reasoning as uaa.ts's rejectNonAssertion (RFC 7522 §2.1): what
  // matters is the document element, not whether the attributes this
  // handler reads happen to appear somewhere in the document.
  // `<hello AssertionConsumerServiceURL="…" ID="_x"/>` parses fine and
  // carries both, so a check that stopped at "did the attributes decode"
  // would build a full signed response for it.
  it('refuses well-formed XML whose document element is not an AuthnRequest', async () => {
    const idp = await startMockSamlIdp();
    try {
      const xml = `<hello AssertionConsumerServiceURL="http://127.0.0.1:1/cb" ID="_x"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      const text = await res.text();
      // Exact fragment the document-element check produces, not the bare
      // `/AuthnRequest/` token: every attribute refusal below also names
      // AuthnRequest in its message, so a bare token match stays green even
      // after the document-element check itself is deleted (this fixture
      // has no Version, so it falls through to the Version refusal).
      expect(text).toMatch(/expected the document element/);
      // Distinguishes this refusal from the other three: it parsed fine and
      // did carry AssertionConsumerServiceURL, so neither of those messages
      // is the right explanation.
      expect(text).not.toMatch(/did not parse as XML/);
      expect(text).not.toMatch(/missing AssertionConsumerServiceURL/);
    } finally {
      await idp.close();
    }
  });

  // Proves the namespace half specifically: the local name is exactly
  // "AuthnRequest", so a check that only compared `localName` would accept
  // this. Only requiring the SAML protocol namespace too catches it.
  it('refuses an AuthnRequest local name in the wrong namespace', async () => {
    const idp = await startMockSamlIdp();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:example:not-saml" ` +
        `ID="_req1" Version="2.0" AssertionConsumerServiceURL="http://127.0.0.1:1/cb"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      const text = await res.text();
      // Exact fragment, not the bare `/AuthnRequest/` token: this fixture
      // has Version="2.0" but no IssueInstant, so once the document-element
      // check is deleted it falls through to the IssueInstant refusal,
      // whose message also contains the word "AuthnRequest".
      expect(text).toMatch(/expected the document element/);
      expect(text).not.toMatch(/did not parse as XML/);
      expect(text).not.toMatch(/missing AssertionConsumerServiceURL/);
    } finally {
      await idp.close();
    }
  });

  // Proves the local-name half specifically, the mirror image of the test
  // above. This document element sits in the *real* SAML protocol
  // namespace and carries both AssertionConsumerServiceURL and ID — a
  // check that only compared `namespaceURI` would accept it. A
  // `samlp:LogoutRequest` is exactly the kind of correctly-namespaced,
  // wrongly-named request a whole-`if`-disabled mutation proof cannot
  // distinguish from `<hello>`: `<hello>` also fails the namespace half
  // (its namespaceURI is null), so deleting only the local-name comparison
  // leaves that test green. Only a same-namespace, different-name document
  // element exposes it.
  it('signs the Response itself when asked to', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp({
      acsUrls: [`${acs.url}/callback`],
      signWhat: 'response',
    });
    try {
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(authnRequest(`${acs.url}/callback`))}`,
      );
      const xml = Buffer.from(acs.received[0].SAMLResponse, 'base64').toString(
        'utf8',
      );
      // Two properties, and neither is document order: `signXml` appends the
      // Signature to the element it references, so in this mode it lands *after*
      // the Assertion, and asserting otherwise would fail against a correct
      // implementation. What matters is which element it references and whose
      // child it is.
      const responseId = /<samlp:Response[^>]*\sID="([^"]+)"/.exec(xml)?.[1];
      expect(responseId).toBeTruthy();
      expect(xml).toContain(`URI="#${responseId}"`);

      const doc = new DOMParser().parseFromString(xml, 'text/xml');
      const signature = doc.getElementsByTagNameNS(
        'http://www.w3.org/2000/09/xmldsig#',
        'Signature',
      )[0];
      expect(signature.parentNode?.localName).toBe('Response');
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('still signs the Assertion when not asked', async () => {
    const acs = await startAcs();
    const idp = await startMockSamlIdp({ acsUrls: [`${acs.url}/callback`] });
    try {
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(authnRequest(`${acs.url}/callback`))}`,
      );
      const xml = Buffer.from(acs.received[0].SAMLResponse, 'base64').toString(
        'utf8',
      );
      const assertionId = /<saml:Assertion[^>]*\sID="([^"]+)"/.exec(xml)?.[1];
      expect(xml).toContain(`URI="#${assertionId}"`);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('refuses a correctly namespaced document element that is not an AuthnRequest', async () => {
    const idp = await startMockSamlIdp();
    try {
      const xml =
        `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" AssertionConsumerServiceURL="http://127.0.0.1:1/cb"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      const text = await res.text();
      // Exact fragment, not the bare `/AuthnRequest/` token: this fixture
      // has Version="2.0" but no IssueInstant, so once the document-element
      // check is deleted it falls through to the IssueInstant refusal,
      // whose message also contains the word "AuthnRequest".
      expect(text).toMatch(/expected the document element/);
      expect(text).not.toMatch(/did not parse as XML/);
      expect(text).not.toMatch(/missing AssertionConsumerServiceURL/);
    } finally {
      await idp.close();
    }
  });
});

/**
 * Finding 1: the SAML twin of clients.ts's refusedUnregisteredRedirectUri.
 * `SamlOptions.acsUrls` is the service-provider metadata a real IdP would
 * consult before trusting AssertionConsumerServiceURL; there is no
 * permissive default, because a fixed one cannot work when every test's ACS
 * runs on an ephemeral port. Every case here uses `authnRequest()`, which
 * carries a valid ID/Version/IssueInstant, so a deleted registration check
 * would let the request fall through to a full signed delivery rather than
 * being masked by an unrelated 400.
 */
describe('mock SAML IdP — ACS registration', () => {
  it('refuses an unregistered ACS with 400 and delivers nothing to it', async () => {
    const acs = await startAcs();
    // Registered, but not with the ACS this AuthnRequest actually names —
    // proves membership is checked, not just "acsUrls is non-empty".
    const idp = await startMockSamlIdp({
      acsUrls: ['http://127.0.0.1:1/not-the-acs'],
    });
    try {
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(
          authnRequest(`${acs.url}/callback`),
        )}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(/not registered/);
      expect(acs.received).toHaveLength(0);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('accepts a registered ACS', async () => {
    const acs = await startAcs();
    const acsUrl = `${acs.url}/callback`;
    const idp = await startMockSamlIdp({ acsUrls: [acsUrl] });
    try {
      await visit(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(authnRequest(acsUrl))}`,
      );
      expect(acs.received).toHaveLength(1);
      expect(acs.received[0].SAMLResponse).toBeTruthy();
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('refuses every AuthnRequest when the IdP has no acsUrls registered at all', async () => {
    const idp = await startMockSamlIdp();
    try {
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(
          authnRequest('http://127.0.0.1:1/cb'),
        )}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(/no ACS URLs are registered/);
    } finally {
      await idp.close();
    }
  });

  // Exactness, pinned the way clients.ts's redirect_uri match already is:
  // a trailing slash makes it a different string, not a different URL a
  // human would call "the same". A prefix- or origin-matching
  // implementation would wrongly accept this.
  it('refuses an ACS that differs from the registered one only by a trailing slash', async () => {
    const acs = await startAcs();
    const registered = `${acs.url}/callback`;
    const idp = await startMockSamlIdp({ acsUrls: [registered] });
    try {
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(
          authnRequest(`${registered}/`),
        )}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(/not registered/);
      expect(acs.received).toHaveLength(0);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('refuses an ACS on the same origin as the registered one but a different path', async () => {
    const acs = await startAcs();
    const registered = `${acs.url}/callback`;
    const idp = await startMockSamlIdp({ acsUrls: [registered] });
    try {
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(
          authnRequest(`${acs.url}/callback-other`),
        )}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(/not registered/);
      expect(acs.received).toHaveLength(0);
    } finally {
      await idp.close();
      await acs.close();
    }
  });
});

/**
 * Finding 2: SAML Core §3.2.1 makes ID, Version and IssueInstant required on
 * every RequestAbstractType, AuthnRequest included. Each case below is
 * registered with the ACS it names, so a deleted check would let the
 * request fall through to a full signed delivery rather than being masked
 * by the ACS-registration refusal above — the same reasoning that governs
 * every other mutation-proof case in this file.
 */
describe('mock SAML IdP — AuthnRequest required attributes (SAML Core §3.2.1)', () => {
  async function idpAndAcs(): Promise<{
    idp: Awaited<ReturnType<typeof startMockSamlIdp>>;
    acsUrl: string;
    close(): Promise<void>;
  }> {
    const acs = await startAcs();
    const acsUrl = `${acs.url}/callback`;
    const idp = await startMockSamlIdp({ acsUrls: [acsUrl] });
    return {
      idp,
      acsUrl,
      close: async () => {
        await idp.close();
        await acs.close();
      },
    };
  }

  it('refuses an AuthnRequest with no ID attribute', async () => {
    const { idp, acsUrl, close } = await idpAndAcs();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `Version="2.0" IssueInstant="${new Date().toISOString()}" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(/missing a required ID attribute/);
    } finally {
      await close();
    }
  });

  // Finding 2 (fifth review, PR #1): SAML gives ID the xs:ID (NCName) type,
  // so a non-empty value that is not an NCName was previously accepted and
  // flowed straight into InResponseTo. The assertion targets a fragment
  // ("must be an NCName") that appears in no other refusal in this suite,
  // including the "missing a required ID attribute" case right above —
  // a shared prefix there would have kept this test green even after the
  // shape check it protects was deleted.
  it('refuses an AuthnRequest ID attribute that contains a space', async () => {
    const { idp, acsUrl, close } = await idpAndAcs();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="contains spaces" Version="2.0" IssueInstant="${new Date().toISOString()}" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(/must be an NCName/);
    } finally {
      await close();
    }
  });

  it('refuses an AuthnRequest ID attribute that starts with a digit', async () => {
    const { idp, acsUrl, close } = await idpAndAcs();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="123" Version="2.0" IssueInstant="${new Date().toISOString()}" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(/must be an NCName/);
    } finally {
      await close();
    }
  });

  it('accepts an AuthnRequest ID attribute that is a conventional SAML id', async () => {
    const { idp, acsUrl, close } = await idpAndAcs();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_a1b2c3" Version="2.0" IssueInstant="${new Date().toISOString()}" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(200);
      expect(await res.text()).toMatch(/<form[^>]+method=["']post["']/i);
    } finally {
      await close();
    }
  });

  it('refuses an AuthnRequest whose Version is not exactly "2.0"', async () => {
    const { idp, acsUrl, close } = await idpAndAcs();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="1.0" IssueInstant="${new Date().toISOString()}" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(/Version must be "2\.0".*got 1\.0/);
    } finally {
      await close();
    }
  });

  it('refuses an AuthnRequest with no IssueInstant attribute', async () => {
    const { idp, acsUrl, close } = await idpAndAcs();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(
        /IssueInstant must be a valid xsd:dateTime/,
      );
    } finally {
      await close();
    }
  });

  it('refuses an AuthnRequest whose IssueInstant does not parse as an xsd:dateTime', async () => {
    const { idp, acsUrl, close } = await idpAndAcs();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" IssueInstant="not-a-date" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(
        /IssueInstant must be a valid xsd:dateTime/,
      );
    } finally {
      await close();
    }
  });

  // Proves the XSD_DATE_TIME regex half of isValidIssueInstant specifically.
  // "2026/08/11" is not the xsd:dateTime lexical form the regex requires,
  // but `Date.parse('2026/08/11')` still succeeds — so a check that relied
  // only on `!Number.isNaN(Date.parse(value))` would accept it. Only the
  // regex catches this.
  it('refuses an AuthnRequest whose IssueInstant is a parseable date in the wrong lexical form', async () => {
    const { idp, acsUrl, close } = await idpAndAcs();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" IssueInstant="2026/08/11" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(
        /IssueInstant must be a valid xsd:dateTime/,
      );
    } finally {
      await close();
    }
  });

  // Proves the Date.parse half of isValidIssueInstant specifically, the
  // mirror image of the test above. "2026-13-45T99:99:99Z" matches
  // XSD_DATE_TIME's shape (digits in every position the regex requires) but
  // names an impossible month, day and time, so `Date.parse` returns NaN —
  // a check that relied only on the regex would accept it. Only the
  // Date.parse guard catches this.
  it('refuses an AuthnRequest whose IssueInstant has the right shape but names an impossible date', async () => {
    const { idp, acsUrl, close } = await idpAndAcs();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" IssueInstant="2026-13-45T99:99:99Z" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(
        /IssueInstant must be a valid xsd:dateTime/,
      );
    } finally {
      await close();
    }
  });

  // Finding 1 (fifth review, PR #1): `Date.parse` normalises rather than
  // rejecting an impossible calendar date — "2026-02-30" silently becomes
  // 2 March, so a shape check plus a bare `!Number.isNaN(Date.parse(...))`
  // check accepts it. Only a round-trip through the captured
  // year/month/day/etc. catches a day that does not exist.
  it('refuses an AuthnRequest whose IssueInstant names a day that rolls into the next month (30 February)', async () => {
    const { idp, acsUrl, close } = await idpAndAcs();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" IssueInstant="2026-02-30T00:00:00Z" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(
        /IssueInstant must be a valid xsd:dateTime/,
      );
    } finally {
      await close();
    }
  });

  // Same rule, a different rollover shape: April has 30 days, not 31.
  it('refuses an AuthnRequest whose IssueInstant names a day that rolls into the next month (31 April)', async () => {
    const { idp, acsUrl, close } = await idpAndAcs();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" IssueInstant="2026-04-31T12:00:00Z" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(
        /IssueInstant must be a valid xsd:dateTime/,
      );
    } finally {
      await close();
    }
  });

  // This is what stops someone "fixing" the round-trip with a flat
  // 28-day rule for February: 2028 is a genuine leap year (divisible by 4,
  // not by 100), so 29 February is a real date and must be accepted.
  it('accepts an AuthnRequest whose IssueInstant names a genuine leap day', async () => {
    const acs = await startAcs();
    const acsUrl = `${acs.url}/callback`;
    const idp = await startMockSamlIdp({ acsUrls: [acsUrl] });
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" IssueInstant="2028-02-29T00:00:00Z" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      await visit(`${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`);
      expect(acs.received).toHaveLength(1);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  // Finding 1 (sixth review, PR #1): the old shape regex matched any two
  // digits either side of the offset's colon, and the round-trip never read
  // the offset at all, so an out-of-range offset sailed through as long as
  // the calendar portion was valid. `xsd:dateTime` bounds an offset at
  // ±14:00 (XML Schema Part 2 §3.2.7) — 99 hours and 99 minutes are not a
  // shape problem, they are a range problem the old code never asked about.
  it('refuses an AuthnRequest whose IssueInstant offset is out of range in both fields', async () => {
    const { idp, acsUrl, close } = await idpAndAcs();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" IssueInstant="2026-08-11T12:00:00+99:99" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(
        /IssueInstant must be a valid xsd:dateTime/,
      );
    } finally {
      await close();
    }
  });

  // `+99:99` alone cannot tell an hour bound from a minute bound apart —
  // both fields are out of range at once, so a mutation that dropped either
  // half of `offsetHour > 14 || offsetMinute > 59` would still be caught by
  // the other half and this test would stay green. These two cases isolate
  // one field out of range at a time.
  it('refuses an AuthnRequest whose IssueInstant offset hour alone is out of range (+15:00)', async () => {
    const { idp, acsUrl, close } = await idpAndAcs();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" IssueInstant="2026-08-11T12:00:00+15:00" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(
        /IssueInstant must be a valid xsd:dateTime/,
      );
    } finally {
      await close();
    }
  });

  it('refuses an AuthnRequest whose IssueInstant offset minute alone is out of range (+05:99)', async () => {
    const { idp, acsUrl, close } = await idpAndAcs();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" IssueInstant="2026-08-11T12:00:00+05:99" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(
        /IssueInstant must be a valid xsd:dateTime/,
      );
    } finally {
      await close();
    }
  });

  // The case that stops someone "fixing" this with a flat `hours < 14`:
  // +14:00 is exactly the legal maximum (14 hours, 0 minutes) and must be
  // accepted, while +14:01 has the same, in-range hour but a minute that
  // only the "hours === 14 implies minutes === 0" half of the rule catches.
  // A check that only bounded the hour would wrongly accept this.
  it('refuses an AuthnRequest whose IssueInstant offset has the maximum hour but a non-zero minute (+14:01)', async () => {
    const { idp, acsUrl, close } = await idpAndAcs();
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" IssueInstant="2026-08-11T12:00:00+14:01" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(
        /IssueInstant must be a valid xsd:dateTime/,
      );
    } finally {
      await close();
    }
  });

  // Pins the *other* half of the "hour === 14 implies minute === 0"
  // conjunct: a mutation that dropped the hour===14 guard and refused any
  // non-zero minute outright — regardless of hour — would still pass every
  // other offset case in this file (they all use minute 00, or an hour
  // already out of range), and only this in-range, non-14, non-zero-minute
  // offset catches it.
  it('accepts an AuthnRequest whose IssueInstant offset has a non-zero minute at an hour below the maximum (+05:30)', async () => {
    const acs = await startAcs();
    const acsUrl = `${acs.url}/callback`;
    const idp = await startMockSamlIdp({ acsUrls: [acsUrl] });
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" IssueInstant="2026-08-11T12:00:00+05:30" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      await visit(`${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`);
      expect(acs.received).toHaveLength(1);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('accepts an AuthnRequest whose IssueInstant offset is the legal maximum (+14:00)', async () => {
    const acs = await startAcs();
    const acsUrl = `${acs.url}/callback`;
    const idp = await startMockSamlIdp({ acsUrls: [acsUrl] });
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" IssueInstant="2026-08-11T12:00:00+14:00" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      await visit(`${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`);
      expect(acs.received).toHaveLength(1);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  it('accepts an AuthnRequest whose IssueInstant offset is the legal minimum (-14:00)', async () => {
    const acs = await startAcs();
    const acsUrl = `${acs.url}/callback`;
    const idp = await startMockSamlIdp({ acsUrls: [acsUrl] });
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" IssueInstant="2026-08-11T12:00:00-14:00" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      await visit(`${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`);
      expect(acs.received).toHaveLength(1);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  // A bare `Z` (UTC) must still be accepted — it is what every AuthnRequest
  // this family actually builds emits, and it is the branch that skips the
  // offset bounds check entirely rather than exercising it with 00:00.
  it('accepts an AuthnRequest whose IssueInstant carries a plain Z offset', async () => {
    const acs = await startAcs();
    const acsUrl = `${acs.url}/callback`;
    const idp = await startMockSamlIdp({ acsUrls: [acsUrl] });
    try {
      const xml =
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
        `ID="_req1" Version="2.0" IssueInstant="2026-08-11T12:00:00Z" ` +
        `AssertionConsumerServiceURL="${acsUrl}"/>`;
      const encoded = deflateRawSync(Buffer.from(xml, 'utf8')).toString(
        'base64',
      );
      await visit(`${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`);
      expect(acs.received).toHaveLength(1);
    } finally {
      await idp.close();
      await acs.close();
    }
  });
});

/**
 * Finding 3 (sixth review, PR #1): SAML Core §3.2.1 requires a recipient to
 * reject a message whose *present* `Destination` names an endpoint other
 * than the one it actually arrived at (the same rule the IdP's own outgoing
 * `Response@Destination` is built to satisfy). `Destination` is optional on
 * `RequestAbstractType`, so its absence is accepted — deliberately, not by
 * omission: see the comment on the check in `src/saml.ts`. The IdP's own
 * `/sso` URL is not known until the socket binds, so each case here builds
 * its `AuthnRequest` after `startMockSamlIdp` resolves, the same ordering
 * `holder` inside `src/saml.ts` requires of itself.
 */
describe('mock SAML IdP — AuthnRequest Destination (SAML Core §3.2.1)', () => {
  function authnRequestWithDestination(
    acsUrl: string,
    destination: string | undefined,
  ): string {
    const destinationAttr =
      destination === undefined ? '' : ` Destination="${destination}"`;
    const xml =
      `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
      `ID="_req1" Version="2.0" IssueInstant="${new Date().toISOString()}"${destinationAttr} ` +
      `AssertionConsumerServiceURL="${acsUrl}"/>`;
    return deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64');
  }

  it('refuses an AuthnRequest whose Destination names a different endpoint', async () => {
    const acs = await startAcs();
    const acsUrl = `${acs.url}/callback`;
    const idp = await startMockSamlIdp({ acsUrls: [acsUrl] });
    try {
      const encoded = authnRequestWithDestination(
        acsUrl,
        'https://other-idp.example/sso',
      );
      const res = await fetch(
        `${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`,
      );
      expect(res.status).toBe(400);
      expect(await res.text()).toMatch(/Destination does not match/);
      expect(acs.received).toHaveLength(0);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  // Proves the check reads the attribute rather than always refusing:
  // naming this very IdP's own /sso endpoint must succeed.
  it("accepts an AuthnRequest whose Destination matches this IdP's own endpoint", async () => {
    const acs = await startAcs();
    const acsUrl = `${acs.url}/callback`;
    const idp = await startMockSamlIdp({ acsUrls: [acsUrl] });
    try {
      const encoded = authnRequestWithDestination(acsUrl, `${idp.url}/sso`);
      await visit(`${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`);
      expect(acs.received).toHaveLength(1);
    } finally {
      await idp.close();
      await acs.close();
    }
  });

  // Proves the check reads the attribute rather than always passing: an
  // absent Destination is accepted, distinct from a matching one above —
  // together they show the outcome tracks whether Destination is present
  // and, when present, whether it matches, not a constant verdict.
  it('accepts an AuthnRequest with no Destination attribute at all', async () => {
    const acs = await startAcs();
    const acsUrl = `${acs.url}/callback`;
    const idp = await startMockSamlIdp({ acsUrls: [acsUrl] });
    try {
      const encoded = authnRequestWithDestination(acsUrl, undefined);
      await visit(`${idp.url}/sso?SAMLRequest=${encodeURIComponent(encoded)}`);
      expect(acs.received).toHaveLength(1);
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
    const idp = await startMockSamlIdp({
      variant: 'statusFailure',
      acsUrls: [`${acs.url}/callback`],
    });
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
    const idp = await startMockSamlIdp({
      variant: 'expired',
      acsUrls: [`${acs.url}/callback`],
    });
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
    const idp = await startMockSamlIdp({
      variant: 'notYetValid',
      acsUrls: [`${acs.url}/callback`],
    });
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
    const idp = await startMockSamlIdp({
      variant: 'wrongAudience',
      acsUrls: [`${acs.url}/callback`],
    });
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
    const idp = await startMockSamlIdp({
      variant: 'wrongRecipient',
      acsUrls: [`${acs.url}/callback`],
    });
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
    const idp = await startMockSamlIdp({
      variant: 'wrongIssuer',
      acsUrls: [`${acs.url}/callback`],
    });
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
    const idp = await startMockSamlIdp({
      variant: 'wrongKey',
      acsUrls: [`${acs.url}/callback`],
    });
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
    const idp = await startMockSamlIdp({
      variant: 'tamperedAfterSign',
      acsUrls: [`${acs.url}/callback`],
    });
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
    const idp = await startMockSamlIdp({
      variant: 'wrongDestination',
      acsUrls: [`${acs.url}/callback`],
    });
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
