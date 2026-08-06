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
}

export interface MockSamlIdp extends MockHandle {
  certificatePem: string;
  setVariant(v: SamlVariant): void;
  lastAssertionId(): string | undefined;
  repeatLastAssertion(): void;
}

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
 * change.
 */
function applySigning(
  xml: string,
  variant: SamlVariant,
  key: KeyMaterial,
  otherKey: () => KeyMaterial,
): string {
  if (variant === 'unsigned') return xml;
  const signingKey = variant === 'wrongKey' ? otherKey() : key;
  let signed = signXml(xml, signingKey);
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
      const acsUrl = /AssertionConsumerServiceURL="([^"]*)"/.exec(
        inflated,
      )?.[1];
      const requestId = /\bID="([^"]*)"/.exec(inflated)?.[1] ?? '';
      if (!acsUrl) {
        res.statusCode = 400;
        res.end('missing AssertionConsumerServiceURL');
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
      const signed = applySigning(xml, variant, key, otherKey);
      const samlResponse = Buffer.from(signed, 'utf8').toString('base64');

      res.setHeader('Content-Type', 'text/html');
      res.end(autoSubmitForm(acsUrl, samlResponse, req.query.RelayState));
    },
  });

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
