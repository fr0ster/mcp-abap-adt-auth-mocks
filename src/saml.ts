/**
 * A mock SAML 2.0 IdP.
 *
 * `GET /sso` turns an HTTP-Redirect-bound `AuthnRequest` into an
 * auto-submitting HTML form carrying a `samlp:Response`. It never posts to
 * the ACS itself — that is the seam this whole package exists to exercise,
 * and only a browser (or `visit()`, standing in for one) performs it.
 *
 * `RelayState` travels as its own query parameter alongside `SAMLRequest`
 * under the Redirect binding — never inside the inflated request — and is
 * carried through the form unchanged, including when it is empty (dropping
 * it would misrepresent what the client sent).
 *
 * Every corruption variant changes exactly one field of an otherwise-correct
 * response, so that a verifier's rejection in Task 10 is attributable to
 * that one field rather than to an accumulation of mistakes.
 */

import { randomUUID } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { DOMParser, type Element } from '@xmldom/xmldom';
import { type MockHandle, startServer } from './server';
import { generateKeyMaterial, type KeyMaterial, signXml } from './signing';

export type SamlVariant =
  | 'valid'
  | 'unsigned'
  | 'wrongKey'
  | 'tamperedAfterSign'
  | 'statusFailure'
  | 'expired'
  | 'notYetValid'
  | 'wrongAudience'
  | 'wrongInResponseTo'
  | 'wrongDestination'
  | 'wrongRecipient'
  | 'wrongIssuer';

export interface SamlOptions {
  variant?: SamlVariant;
  audience?: string;
  issuer?: string;
  /**
   * The ACS endpoints this IdP trusts — the SAML twin of `UaaClient.redirectUris`
   * in `src/clients.ts`, and checked the same way: an `AuthnRequest`'s
   * `AssertionConsumerServiceURL` must match one of these **exactly**,
   * byte-for-byte, never by origin or prefix. There is no default, because
   * every test's ACS runs on an ephemeral port and cannot be known in
   * advance. Omitting it entirely refuses every `AuthnRequest` with a `400`
   * naming the missing registration — the faithful model, since a real
   * identity provider with no service-provider metadata has no relying
   * party to deliver an assertion to either.
   */
  acsUrls?: string[];
  /**
   * Which element the signature covers. Defaults to `'assertion'`, which is
   * what every identity provider this package was built against does, and what
   * every existing consumer already gets.
   *
   * `'response'` exists because a relying party may require it — a validator
   * that treats `Status` and `Destination` as controls can only do so when
   * they are inside the signature.
   */
  signWhat?: 'assertion' | 'response';
}

export interface MockSamlIdp extends MockHandle {
  certificatePem: string;
  setVariant(v: SamlVariant): void;
  lastAssertionId(): string | undefined;
  repeatLastAssertion(): void;
}

const SAML_PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';
/**
 * SAML Core §3.2.1 (`RequestAbstractType`) requires `IssueInstant` to be an
 * `xsd:dateTime`. This is XML Schema's canonical (though not sole legal)
 * lexical form — `YYYY-MM-DDTHH:MM:SS` with optional fractional seconds and
 * an optional `Z`/`±HH:MM` offset — and is exactly what every AuthnRequest
 * this family builds actually emits (`new Date().toISOString()`), so it is
 * strict enough to catch a malformed or absent value without rejecting a
 * conformant one.
 *
 * The offset is captured (group 7) rather than merely shape-matched: `xsd:
 * dateTime` bounds it at ±14:00 (hours 00–14, minutes 00–59, and when hours
 * is 14 minutes must be 00), which the shape alone does not express — the
 * regex would happily match `+99:99`.
 */
const XSD_DATE_TIME =
  /^(-?\d{4,})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})?$/;
/**
 * `Date.parse` (and `new Date(string)`) normalises rather than rejecting:
 * `2026-02-30T00:00:00Z` silently becomes 2 March, so a shape check plus a
 * parseability check lets an impossible calendar date through. Calendar
 * validity is checked here by round-trip instead: the year, month, day,
 * hour, minute and second captured straight from the pattern are fed to
 * `Date.UTC`, and every captured field must survive unchanged. A date that
 * rolls over (30 Feb -> 2 Mar, 31 Apr -> 1 May) fails that comparison.
 *
 * The date and time fields are validated exactly as written, independently
 * of any timezone offset — a `Z` or `±hh:mm` suffix does not change whether
 * 30 February exists, so the offset never participates in the round-trip.
 * It is, however, bounds-checked on its own: `xsd:dateTime` caps the offset
 * at ±14:00 (XML Schema Part 2 §3.2.7), so `+14:01` is out of range even
 * though `+14:00` is the legal maximum — a flat `hours < 14` would wrongly
 * refuse the maximum and wrongly accept `+14:59`.
 *
 * Deliberately not implemented, so as not to overstate what this checks:
 * the `xsd:dateTime` end-of-day form (`24:00:00`), leap seconds (`:60`),
 * and the calendar semantics of a negative (BCE) year — none of which any
 * conformant IssueInstant this family emits or accepts actually uses.
 */
function isValidIssueInstant(value: string): boolean {
  const match = XSD_DATE_TIME.exec(value);
  if (!match) return false;
  const [, yearStr, monthStr, dayStr, hourStr, minuteStr, secondStr, offset] =
    match;
  const year = Number(yearStr);
  const month = Number(monthStr);
  const day = Number(dayStr);
  const hour = Number(hourStr);
  const minute = Number(minuteStr);
  const second = Number(secondStr);
  const asUtc = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  const calendarValid =
    asUtc.getUTCFullYear() === year &&
    asUtc.getUTCMonth() === month - 1 &&
    asUtc.getUTCDate() === day &&
    asUtc.getUTCHours() === hour &&
    asUtc.getUTCMinutes() === minute &&
    asUtc.getUTCSeconds() === second;
  if (!calendarValid) return false;
  if (offset === undefined || offset === 'Z') return true;
  const offsetHour = Number(offset.slice(1, 3));
  const offsetMinute = Number(offset.slice(4, 6));
  if (offsetHour > 14 || offsetMinute > 59) return false;
  if (offsetHour === 14 && offsetMinute !== 0) return false;
  return true;
}
/**
 * ASCII subset of the `NCName` production (XML Namespaces 1.0 §3) that
 * `xs:ID` — and so SAML's `AuthnRequest/@ID` — is built on: a leading
 * letter or underscore, then any run of letters, digits, ".", "-" or "_".
 * The full production also admits a wide range of non-ASCII
 * NameStartChar/NameChar code points; those are not implemented here.
 */
const NCNAME_ASCII = /^[A-Za-z_][A-Za-z0-9_.-]*$/;
const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';
const STATUS_RESPONDER_FAILURE = 'urn:oasis:names:tc:SAML:2.0:status:Responder';
const WRONG_ENDPOINT = 'http://127.0.0.1:1/other';
const WRONG_AUDIENCE = 'urn:someone:else';
const WRONG_ISSUER = 'urn:other:idp';
const WRONG_IN_RESPONSE_TO = '_not-the-request';

/** Escapes a value for an HTML attribute delimited by double quotes. */
function escapeAttribute(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function autoSubmitForm(
  acsUrl: string,
  samlResponse: string,
  relayState?: string,
): string {
  const relay =
    relayState === undefined
      ? ''
      : `<input type="hidden" name="RelayState" value="${escapeAttribute(relayState)}"/>`;
  return `<html><body onload="document.forms[0].submit()">
<form method="post" action="${escapeAttribute(acsUrl)}">
<input type="hidden" name="SAMLResponse" value="${escapeAttribute(samlResponse)}"/>
${relay}
</form></body></html>`;
}

interface ResponseParams {
  variant: SamlVariant;
  issuer: string;
  audience: string;
  acsUrl: string;
  requestId: string;
  assertionId: string;
}

/**
 * Builds the `samlp:Response` XML for one delivery, applying the variant's
 * single field change. `Destination` lives on the Response; everything else
 * asked for by the brief (Assertion `ID`/`IssueInstant`/`Issuer`, `Status`,
 * `Conditions`, `SubjectConfirmationData`) is built alongside it so every
 * variant has exactly one place in the document that differs from 'valid'.
 */
function buildResponseXml(p: ResponseParams): string {
  const issueInstant = new Date().toISOString();
  const past = new Date(Date.now() - 60_000).toISOString();
  const future = new Date(Date.now() + 3_600_000).toISOString();

  // Every field below is computed independently of every other: each
  // variant's branch touches exactly one of them, and every other branch
  // falls through to the 'valid' value. That is what keeps a corruption
  // attributable to a single field rather than to a bundle of changes.
  const destination =
    p.variant === 'wrongDestination'
      ? WRONG_ENDPOINT
      : escapeAttribute(p.acsUrl);
  const recipient =
    p.variant === 'wrongRecipient' ? WRONG_ENDPOINT : escapeAttribute(p.acsUrl);
  const issuerValue =
    p.variant === 'wrongIssuer' ? WRONG_ISSUER : escapeAttribute(p.issuer);
  const audienceValue =
    p.variant === 'wrongAudience'
      ? WRONG_AUDIENCE
      : escapeAttribute(p.audience);
  const inResponseTo =
    p.variant === 'wrongInResponseTo'
      ? WRONG_IN_RESPONSE_TO
      : escapeAttribute(p.requestId);
  const notBefore = p.variant === 'notYetValid' ? future : past;
  const notOnOrAfter = p.variant === 'expired' ? past : future;
  const statusValue =
    p.variant === 'statusFailure' ? STATUS_RESPONDER_FAILURE : STATUS_SUCCESS;

  const responseId = `_${randomUUID()}`;

  return (
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseId}" ` +
    `Version="2.0" IssueInstant="${issueInstant}" Destination="${destination}" ` +
    `InResponseTo="${inResponseTo}">` +
    `<saml:Issuer>${issuerValue}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="${statusValue}"/></samlp:Status>` +
    `<saml:Assertion ID="${p.assertionId}" Version="2.0" IssueInstant="${issueInstant}">` +
    `<saml:Issuer>${issuerValue}</saml:Issuer>` +
    `<saml:Subject>` +
    `<saml:NameID>mock-user</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
    `<saml:SubjectConfirmationData Recipient="${recipient}" InResponseTo="${inResponseTo}" NotOnOrAfter="${notOnOrAfter}"/>` +
    `</saml:SubjectConfirmation>` +
    `</saml:Subject>` +
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">` +
    `<saml:AudienceRestriction><saml:Audience>${audienceValue}</saml:Audience></saml:AudienceRestriction>` +
    `</saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${issueInstant}">` +
    `<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>` +
    `</saml:AuthnStatement>` +
    `</saml:Assertion>` +
    `</samlp:Response>`
  );
}

/**
 * Signs (or deliberately mis-signs) the response. 'unsigned' skips signing
 * outright; 'wrongKey' signs with a second, unrelated key pair so the
 * shipped certificate no longer verifies it; 'tamperedAfterSign' signs
 * correctly and then mutates signed content, breaking the reference digest
 * without touching the signature value itself. Every other variant is
 * signed normally — signing is not part of any other variant's one-field
 * change. `signWhat` governs which element the `Reference` names, and is
 * independent of the variant being applied.
 */
function applySigning(
  xml: string,
  variant: SamlVariant,
  key: KeyMaterial,
  otherKey: () => KeyMaterial,
  signWhat: 'assertion' | 'response',
): string {
  if (variant === 'unsigned') return xml;
  const signingKey = variant === 'wrongKey' ? otherKey() : key;
  let signed =
    signWhat === 'response'
      ? signXml(xml, signingKey, {
          referenceXPath: "//*[local-name(.)='Response']",
        })
      : signXml(xml, signingKey);
  if (variant === 'tamperedAfterSign') {
    // Alters signed text content while leaving the document well-formed, so
    // the RSA signature value still checks out and only the reference
    // digest fails.
    signed = signed.replace('mock-user', 'mock-user-tampered');
  }
  return signed;
}

export async function startMockSamlIdp(
  options: SamlOptions = {},
): Promise<MockSamlIdp> {
  const issuer = options.issuer ?? 'mock-idp';
  const audience = options.audience ?? 'mock-sp';
  let variant: SamlVariant = options.variant ?? 'valid';
  const registeredAcsUrls = options.acsUrls;
  const signWhat = options.signWhat ?? 'assertion';

  const key = generateKeyMaterial();
  // Generated lazily: most instances never use the wrongKey variant, and
  // RSA key generation is the slowest thing this module does.
  let secondKey: KeyMaterial | undefined;
  const otherKey = (): KeyMaterial => {
    if (!secondKey) secondKey = generateKeyMaterial();
    return secondKey;
  };

  let lastAssertionId: string | undefined;
  let repeatNext = false;

  // The IdP does not know its own /sso URL until the socket binds — filled
  // in from `handle` right below, before startMockSamlIdp returns, the same
  // mutable-holder shape oidc.ts uses for its discovery document.
  const holder: { baseUrl: string } = { baseUrl: '' };

  const handle = await startServer({
    'GET /sso': (req, res) => {
      const encoded = req.query.SAMLRequest;
      if (!encoded) {
        res.statusCode = 400;
        res.end('missing SAMLRequest');
        return;
      }
      const inflated = inflateRawSync(Buffer.from(encoded, 'base64')).toString(
        'utf8',
      );

      // Parsed with a full XML parser rather than a regex, the same way
      // uaa.ts's rejectNonAssertion reads an Assertion. The plan that
      // shipped the regex justified it on the grounds that the request is
      // one the family builds, so a full parse was not warranted — but a
      // valid AssertionConsumerServiceURL can legitimately carry a query
      // string, which the AuthnRequest transports XML-escaped (e.g.
      // `&amp;`). A regex reads that escaping literally; only a parser's
      // `getAttribute` decodes entities the way the XML spec requires, and
      // this value is echoed into Destination and
      // SubjectConfirmationData@Recipient too, so a decoding mistake here
      // corrupts all three.
      let root: Element | null;
      try {
        root = new DOMParser().parseFromString(
          inflated,
          'text/xml',
        ).documentElement;
      } catch {
        res.statusCode = 400;
        res.end('AuthnRequest did not parse as XML');
        return;
      }
      if (!root) {
        res.statusCode = 400;
        res.end('AuthnRequest did not parse as XML');
        return;
      }
      // The same reasoning as uaa.ts's rejectNonAssertion: what matters is
      // the *document element*, not whether the right attributes appear
      // somewhere in the document. `<hello AssertionConsumerServiceURL="…"
      // ID="_x"/>` parses fine and carries both attributes this handler
      // reads, so a check that stopped at "did the attributes decode" would
      // accept it. A local-name-only check is not enough either — the
      // namespace half is what a forged or mistranslated request is most
      // likely to get wrong while still spelling the tag "AuthnRequest".
      if (
        root.localName !== 'AuthnRequest' ||
        root.namespaceURI !== SAML_PROTOCOL_NS
      ) {
        res.statusCode = 400;
        const seen = root.namespaceURI
          ? `{${root.namespaceURI}}${root.localName}`
          : (root.localName ?? 'an unnamed element');
        res.end(
          `expected the document element to be AuthnRequest in ${SAML_PROTOCOL_NS}, got ${seen}`,
        );
        return;
      }
      // SAML Core §3.2.1 makes ID, Version and IssueInstant required on
      // every RequestAbstractType, AuthnRequest included. Checked here, on
      // the document element already confirmed to be an AuthnRequest, and
      // before anything specific to *this* request type (its ACS) is even
      // read — a request missing one of these three is malformed
      // independently of what it asks for.
      const requestId = root.getAttribute('ID') ?? '';
      if (!requestId) {
        res.statusCode = 400;
        res.end(
          'AuthnRequest is missing a required ID attribute (SAML Core §3.2.1, RequestAbstractType)',
        );
        return;
      }
      // SAML Core §3.2.1 gives ID the XML Schema `xs:ID` type, whose value
      // space is `NCName`: no leading digit, and no spaces or colons
      // anywhere. A non-empty string that violates that shape (e.g.
      // "123" or "contains spaces") was previously accepted and flowed
      // straight into InResponseTo. This checks the ASCII subset of
      // NCName only — a leading letter or underscore, then letters,
      // digits, ".", "-" or "_" — and deliberately does not implement the
      // full production's Unicode NameStartChar/NameChar ranges, which no
      // ID this family mints or expects ever needs.
      if (!NCNAME_ASCII.test(requestId)) {
        res.statusCode = 400;
        res.end(
          `AuthnRequest ID attribute must be an NCName (SAML Core §3.2.1, RequestAbstractType uses xs:ID): a leading letter or underscore, then letters, digits, ".", "-", "_" (ASCII subset), got "${requestId}"`,
        );
        return;
      }
      const version = root.getAttribute('Version');
      if (version !== '2.0') {
        res.statusCode = 400;
        res.end(
          `AuthnRequest Version must be "2.0" (SAML Core §3.2.1, RequestAbstractType), got ${version ?? 'none'}`,
        );
        return;
      }
      const issueInstant = root.getAttribute('IssueInstant');
      // `!issueInstant ||` is not logically load-bearing: `getAttribute`
      // returns `string | null`, and `XSD_DATE_TIME.test(null)` already
      // evaluates to `false` (RegExp#test coerces its argument to the
      // string "null"), so `isValidIssueInstant` would return `false` for a
      // missing attribute on its own. It stays because `isValidIssueInstant`
      // is typed to take `string`, not `string | null` — this is the
      // narrowing TypeScript needs to allow the call at all, kept as a
      // defensive/type guard rather than as a rule a test proves.
      if (!issueInstant || !isValidIssueInstant(issueInstant)) {
        res.statusCode = 400;
        res.end(
          'AuthnRequest IssueInstant must be a valid xsd:dateTime (SAML Core §3.2.1, RequestAbstractType)',
        );
        return;
      }
      // SAML Core §3.2.1: `Destination` on `RequestAbstractType` is optional,
      // but a recipient that receives a message carrying one must check it
      // names the endpoint the message actually arrived at — otherwise a
      // request built for one IdP's /sso could be replayed at another IdP
      // that happens to trust the same relying party. Absence is a
      // deliberate choice, not an oversight: this family's own AuthnRequest
      // builder never sets Destination, and there is nothing to compare
      // against when it is missing, so an absent attribute is accepted
      // rather than treated as a proxy for "wrong".
      const destination = root.getAttribute('Destination');
      const ownEndpoint = `${holder.baseUrl}/sso`;
      if (destination !== null && destination !== ownEndpoint) {
        res.statusCode = 400;
        res.end(
          `AuthnRequest Destination does not match this IdP's endpoint (SAML Core §3.2.1), expected ${ownEndpoint}, got ${destination}`,
        );
        return;
      }

      const acsUrl =
        root.getAttribute('AssertionConsumerServiceURL') || undefined;
      if (!acsUrl) {
        res.statusCode = 400;
        res.end('missing AssertionConsumerServiceURL');
        return;
      }
      // The SAML twin of clients.ts's refusedUnregisteredRedirectUri:
      // AssertionConsumerServiceURL is client-supplied, and trusting it
      // without checking it against service-provider metadata would let a
      // forged AuthnRequest aim a signed assertion at an attacker's URL.
      // Omitting acsUrls entirely is not a permissive default — it means
      // this IdP has no service-provider metadata at all, so it refuses
      // every request, exactly as a real IdP would have no relying party to
      // deliver to. Registered means registered exactly: RFC 6749 §3.1.2.3's
      // byte-for-byte comparison, restated here because the two checks are
      // the same rule wearing different protocol names.
      if (registeredAcsUrls === undefined) {
        res.statusCode = 400;
        res.end(
          'no ACS URLs are registered for this IdP: pass SamlOptions.acsUrls to register the AssertionConsumerServiceURL an AuthnRequest may name',
        );
        return;
      }
      if (!registeredAcsUrls.includes(acsUrl)) {
        res.statusCode = 400;
        res.end(
          'AssertionConsumerServiceURL is not registered for this IdP (SamlOptions.acsUrls)',
        );
        return;
      }

      // repeatLastAssertion() is one-shot: it reuses the stored ID for
      // exactly the next response, then reverts to minting fresh ones.
      const assertionId =
        repeatNext && lastAssertionId !== undefined
          ? lastAssertionId
          : `_${randomUUID()}`;
      repeatNext = false;
      lastAssertionId = assertionId;

      const xml = buildResponseXml({
        variant,
        issuer,
        audience,
        acsUrl,
        requestId,
        assertionId,
      });
      const signed = applySigning(xml, variant, key, otherKey, signWhat);
      const samlResponse = Buffer.from(signed, 'utf8').toString('base64');

      res.setHeader('Content-Type', 'text/html');
      res.end(autoSubmitForm(acsUrl, samlResponse, req.query.RelayState));
    },
  });

  holder.baseUrl = handle.url;

  return {
    ...handle,
    certificatePem: key.certificatePem,
    setVariant: (v: SamlVariant): void => {
      variant = v;
    },
    lastAssertionId: (): string | undefined => lastAssertionId,
    repeatLastAssertion: (): void => {
      repeatNext = true;
    },
  };
}
