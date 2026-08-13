import { deflateRawSync } from 'node:zlib';
import { describe, expect, it } from '@jest/globals';
import {
  type CacheItem,
  type CacheProvider,
  SAML,
  ValidateInResponseTo,
} from '@node-saml/node-saml';
import { visit } from '../browser';
import { type SamlVariant, startMockSamlIdp } from '../saml';
import { startServer } from '../server';

const REQUEST_ID = '_req1';

/**
 * The request-ID cache node-saml needs. `InMemoryCacheProvider` exists in the
 * package but is not exported from its index, so this is the smallest thing
 * satisfying the published interface — plus `seed`, because our AuthnRequest is
 * built by hand and never passes through node-saml's own request generation.
 */
function requestIdCache(): CacheProvider & { seed(id: string): void } {
  const keys = new Map<string, CacheItem>();
  return {
    seed(id) {
      keys.set(id, { value: new Date().toISOString(), createdAt: Date.now() });
    },
    async saveAsync(key, value) {
      const item = { value, createdAt: Date.now() };
      keys.set(key, item);
      return item;
    },
    async getAsync(key) {
      return keys.get(key)?.value ?? null;
    },
    async removeAsync(key) {
      if (key === null) return null;
      return keys.delete(key) ? key : null;
    },
  };
}

/** An IdP and an ACS, wired together, able to deliver more than once. */
async function session(variant?: SamlVariant) {
  const received: Record<string, string>[] = [];
  const acs = await startServer({
    'POST /callback': (req, res) => {
      received.push(req.body);
      res.end('ok');
    },
  });
  const acsUrl = `${acs.url}/callback`;
  const idp = await startMockSamlIdp(
    variant ? { variant, acsUrls: [acsUrl] } : { acsUrls: [acsUrl] },
  );
  const xml =
    `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `ID="${REQUEST_ID}" Version="2.0" IssueInstant="${new Date().toISOString()}" ` +
    `AssertionConsumerServiceURL="${acsUrl}"/>`;
  const request = deflateRawSync(Buffer.from(xml, 'utf8')).toString('base64');

  return {
    idp,
    acsUrl,
    async deliver(): Promise<string> {
      await visit(`${idp.url}/sso?SAMLRequest=${encodeURIComponent(request)}`);
      return received[received.length - 1].SAMLResponse;
    },
    async close() {
      await idp.close();
      await acs.close();
    },
  };
}

function verifier(
  cert: string,
  acsUrl: string,
  cacheProvider: CacheProvider,
): SAML {
  return new SAML({
    idpCert: cert,
    idpIssuer: 'mock-idp',
    issuer: 'mock-sp',
    audience: 'mock-sp',
    callbackUrl: acsUrl,
    wantAssertionsSigned: true,
    // Task 8 signs the Assertion, as SAP identity providers do. Left at its
    // default of true, this option would fail every case for the same reason.
    wantAuthnResponseSigned: false,
    validateInResponseTo: ValidateInResponseTo.always,
    cacheProvider,
  });
}

/** A verifier that has seen nothing yet, with the request ID it expects. */
function freshVerifier(cert: string, acsUrl: string): SAML {
  const cache = requestIdCache();
  cache.seed(REQUEST_ID);
  return verifier(cert, acsUrl, cache);
}

describe('an independent verifier judges the mock', () => {
  it('accepts the valid assertion', async () => {
    const s = await session();
    try {
      const payload = await s.deliver();
      await expect(
        freshVerifier(s.idp.certificatePem, s.acsUrl).validatePostResponseAsync(
          {
            SAMLResponse: payload,
          },
        ),
      ).resolves.toBeDefined();
    } finally {
      await s.close();
    }
  }, 20000);

  /**
   * Why each variant must be rejected — not merely that it was.
   *
   * `rejects.toThrow()` with no pattern is how this task nearly shipped a lie:
   * a structural defect in the signature's placement (fixed in `signing.ts`)
   * caused seven of the original nine `rejected` cases to be refused for that
   * one unrelated reason, so their corruption logic could have been deleted
   * with every case still green. Pin the reason.
   *
   * Every pattern below was filled from the message node-saml *actually*
   * produces (see the report for the full observed list), not guessed.
   *
   * `unsigned`, `wrongKey` and `tamperedAfterSign` share one pattern
   * deliberately, not as a shortcut: node-saml has exactly one throw site for
   * this string (`saml.js:541`, `if (!assertionVerifiedXml) throw new
   * Error("Invalid signature")`), and it is reached identically whether the
   * Assertion carries no Signature at all, a Signature made with the wrong
   * key, or a Signature whose digest no longer matches tampered content.
   * There is no more specific message to distinguish them — inventing three
   * different regexes here would assert a distinction the verifier does not
   * make.
   *
   * `statusFailure` and `wrongIssuer` are not in this table: node-saml
   * accepts both (see the `unchecked` list below, with source citations for
   * why).
   */
  const REASON: Record<string, RegExp> = {
    unsigned: /^Invalid signature$/,
    wrongKey: /^Invalid signature$/,
    tamperedAfterSign: /^Invalid signature$/,
    expired: /No valid subject confirmation found/,
    notYetValid: /SAML assertion not yet valid/,
    wrongAudience: /SAML assertion audience mismatch/,
    wrongInResponseTo: /InResponseTo is not valid/,
  };

  // Derived from REASON, not iterated alongside it: a variant added to
  // REASON without a real pattern cannot compile as a valid RegExp entry,
  // and a variant that never gets a pattern here never gets a test either —
  // there is no separate list to fall out of sync with it. `rejects.toThrow(undefined)`
  // degrades to "throws anything", so keeping these two inseparable is what
  // stops that degradation from being silent.
  for (const variant of Object.keys(REASON) as SamlVariant[]) {
    it(`rejects ${variant}`, async () => {
      const s = await session(variant);
      try {
        const payload = await s.deliver();
        await expect(
          freshVerifier(
            s.idp.certificatePem,
            s.acsUrl,
          ).validatePostResponseAsync({
            SAMLResponse: payload,
          }),
        ).rejects.toThrow(REASON[variant]);
      } finally {
        await s.close();
      }
    }, 20000);
  }

  type Session = Awaited<ReturnType<typeof session>>;

  // Every one of these the verifier does not check at all. Asserting
  // rejection would be asserting a check that does not exist; asserting the
  // corruption is present keeps the variant honest and names the gap our own
  // validator must close. If any of these ever starts rejecting, node-saml
  // gained a check — move the variant into `rejected` above rather than
  // relaxing the assertion.
  const unchecked: Array<{
    variant: SamlVariant;
    /** Proves the corruption is actually present in the delivered XML. */
    assertCorrupted: (xml: string, s: Session) => void;
  }> = [
    {
      variant: 'wrongDestination',
      assertCorrupted: (xml, s) => {
        const value = /Destination="([^"]*)"/.exec(xml)?.[1];
        expect(value).toBeTruthy();
        expect(value).not.toBe(s.acsUrl);
      },
    },
    {
      variant: 'wrongRecipient',
      assertCorrupted: (xml, s) => {
        const value = /Recipient="([^"]*)"/.exec(xml)?.[1];
        expect(value).toBeTruthy();
        expect(value).not.toBe(s.acsUrl);
      },
    },
    // Moved here from `rejected` after the signing fix: with the Signature
    // correctly placed, this still resolves. node-saml's
    // `validatePostResponseAsync` only ever inspects the Response's
    // top-level `<Status>` in the branch gated by `if (!("Assertion" in
    // response))` (saml.js:576-604) — the *only* StatusCode check in the
    // file. Whenever a validly-signed Assertion is present, control never
    // reaches that branch: `if (verifiedXml && assertions.length +
    // encryptedAssertions.length == 1)` (saml.js:563) short-circuits
    // straight into `processValidlySignedAssertionAsync`, which never reads
    // `Status` at all. A Responder-failure Status accompanied by a validly
    // signed Assertion is accepted.
    {
      variant: 'statusFailure',
      assertCorrupted: (xml) => {
        const value = /<samlp:StatusCode Value="([^"]*)"/.exec(xml)?.[1];
        expect(value).toBe('urn:oasis:names:tc:SAML:2.0:status:Responder');
      },
    },
    // Moved here from `rejected` after the signing fix, for the same reason.
    // `idpIssuer` (saml.js:725, inside `verifyIssuer`) is read only by
    // `verifyLogoutRequest` and `verifyLogoutResponse` — `verifyIssuer` is
    // never called from `validatePostResponseAsync`.
    // `processValidlySignedAssertionAsync` (saml.js:748) reads the
    // Assertion's own `Issuer` only to populate `profile.issuer` for the
    // caller; it is never compared against `idpIssuer`. The mock corrupts
    // the Issuer on both the Response and the Assertion (per Task 8), so
    // both copies are checked here even though the verifier examines
    // neither.
    {
      variant: 'wrongIssuer',
      assertCorrupted: (xml) => {
        const issuers = [
          ...xml.matchAll(/<saml:Issuer>([^<]*)<\/saml:Issuer>/g),
        ].map((m) => m[1]);
        expect(issuers.length).toBeGreaterThanOrEqual(2);
        for (const value of issuers) expect(value).not.toBe('mock-idp');
      },
    },
  ];

  for (const { variant, assertCorrupted } of unchecked) {
    it(`corrupts ${variant}, which this verifier does not examine`, async () => {
      const s = await session(variant);
      try {
        const payload = await s.deliver();
        const xml = Buffer.from(payload, 'base64').toString('utf8');
        assertCorrupted(xml, s);
        // `resolves.toBeDefined()` is satisfied by a resolved value of
        // `null` too, so it would stay green even if a future node-saml
        // answered a corrupted response with a null profile instead of
        // throwing. Asserting the NameID the mock actually put in the
        // assertion (`<saml:NameID>mock-user</saml:NameID>`, see saml.ts)
        // proves the response was genuinely parsed and accepted, not merely
        // resolved.
        await expect(
          freshVerifier(
            s.idp.certificatePem,
            s.acsUrl,
          ).validatePostResponseAsync({
            SAMLResponse: payload,
          }),
        ).resolves.toMatchObject({ profile: { nameID: 'mock-user' } });
      } finally {
        await s.close();
      }
    }, 20000);
  }

  // Replay, stated for exactly what can be proven here.
  //
  // No off-the-shelf verifier detects replay, because remembering assertions is
  // the relying party's job — the job issue #19 will build. What this task can
  // establish, without writing that validator, is the pair of facts that make
  // replay dangerous:
  //
  //   1. both deliveries carry the same assertion ID (structural), and
  //   2. each one is independently valid — a verifier that has seen nothing
  //      accepts both.
  //
  // Nothing in the second message is malformed. Only a memory of the first can
  // reject it, and there is nothing off the shelf that keeps one.
  it('produces two individually valid deliveries sharing one assertion ID', async () => {
    const s = await session();
    try {
      const first = await s.deliver();
      const firstId = s.idp.lastAssertionId();
      expect(firstId).toBeTruthy();

      s.idp.repeatLastAssertion();
      const second = await s.deliver();

      const assertionIdOf = (payload: string): string | undefined =>
        /<(?:\w+:)?Assertion[^>]*\bID="([^"]+)"/.exec(
          Buffer.from(payload, 'base64').toString('utf8'),
        )?.[1];

      expect(assertionIdOf(first)).toBe(firstId);
      expect(assertionIdOf(second)).toBe(firstId);

      // Judged alone, each is beyond reproach — including the replay.
      await expect(
        freshVerifier(s.idp.certificatePem, s.acsUrl).validatePostResponseAsync(
          {
            SAMLResponse: first,
          },
        ),
      ).resolves.toBeDefined();
      await expect(
        freshVerifier(s.idp.certificatePem, s.acsUrl).validatePostResponseAsync(
          {
            SAMLResponse: second,
          },
        ),
      ).resolves.toBeDefined();
    } finally {
      await s.close();
    }
  }, 30000);

  // A neighbouring property, easy to mistake for replay detection and not the
  // same thing. node-saml's request-ID cache is one-shot: a successful
  // validation consumes the InResponseTo, so any later response naming the same
  // AuthnRequest is rejected — whatever its assertion ID. Pinned here precisely
  // so nobody reads it as evidence about assertions. Note the second delivery
  // is a *fresh* assertion, and is refused all the same.
  it('consumes the request ID, rejecting a second response to one AuthnRequest', async () => {
    const s = await session();
    try {
      const cache = requestIdCache();
      cache.seed(REQUEST_ID);
      const remembers = verifier(s.idp.certificatePem, s.acsUrl, cache);

      await expect(
        remembers.validatePostResponseAsync({
          SAMLResponse: await s.deliver(),
        }),
      ).resolves.toBeDefined();
      const firstId = s.idp.lastAssertionId();

      const another = await s.deliver();
      expect(s.idp.lastAssertionId()).not.toBe(firstId);
      // Pinned like every other rejection in this file. Left bare, a
      // signature-placement regression like the one this task already found
      // once would throw "Invalid signature: Referenced node does not refer
      // to it's parent element" here too, and `rejects.toThrow()` would still
      // pass — this test would go on claiming the request-ID cache is
      // one-shot while proving nothing of the kind.
      await expect(
        remembers.validatePostResponseAsync({ SAMLResponse: another }),
      ).rejects.toThrow(/^InResponseTo is not valid$/);
    } finally {
      await s.close();
    }
  }, 30000);
});
