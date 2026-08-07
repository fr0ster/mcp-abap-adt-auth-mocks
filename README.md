# @mcp-abap-adt/auth-mocks

Protocol-faithful mock authorization servers (UAA/OAuth2, OIDC, SAML IdP) for
testing `@mcp-abap-adt` packages.

## Installation

```bash
npm install --save-dev @mcp-abap-adt/auth-mocks
```

## Overview

This package is a standalone developer tool: it speaks HTTP, OAuth2 and SAML,
and imports nothing from `@mcp-abap-adt/*`. It exists so that other packages in
the family can test their authorization flows against a mock UAA/OAuth2
server, a mock OIDC provider and a mock SAML identity provider —
deterministically, without a live tenant.

Every mock starts and stops inside a test; nothing here is meant to run in
production. Each `start*` function returns a handle with `.url`, `.port`,
`.requests` (every request the mock received, oldest first, for assertions)
and `close()`.

**These mocks do not replace live testing.** They prove the mock's own
behaviour is internally consistent and, for SAML, that an independent
verifier accepts what it should and rejects what it checks — they do not
prove the mock's wire format matches a real UAA, a real OIDC provider or a
real identity provider. See
["What signature verification here does and does not prove"](#what-signature-verification-here-does-and-does-not-prove)
below for exactly what is and is not established, and keep running the real
thing against a live tenant.

## Quick start: `visit` and the `openUrl` seam

None of the mocks post a SAML assertion to the ACS themselves, and none of
them are reached without someone following a redirect. That someone is
normally a browser. `visit()` is a fake one, reduced to exactly what an
authorization flow needs: it follows HTTP redirects and, when it lands on an
auto-submitting HTML form (how the SAML POST binding works), it submits that
form too.

`visit` exists to be handed to whatever seam a consumer already uses to open
a browser. In `@mcp-abap-adt/auth-providers`, that seam is `openUrl` on the
default strategies (`browserCallbackStrategy`, `oidcCallbackStrategy`,
`samlCallbackStrategy`) — the provider builds an authorization URL and calls
`openUrl` with it instead of launching Chrome:

```ts
import { startMockUaa, visit } from '@mcp-abap-adt/auth-mocks';
import {
  AuthorizationCodeProvider,
  browserCallbackStrategy,
} from '@mcp-abap-adt/auth-providers';

const uaa = await startMockUaa();
try {
  const provider = new AuthorizationCodeProvider({
    uaaUrl: uaa.url,
    clientId: 'mock-client',
    clientSecret: 'mock-secret',
    authorization: browserCallbackStrategy({
      // openUrl's signature also carries a browser name and the bound
      // redirect URI, neither of which visit() needs — it only wants the
      // URL to fetch.
      openUrl: async (url) => {
        await visit(url);
      },
    }),
  });

  const { authorizationToken } = await provider.getTokens();
} finally {
  await uaa.close();
}
```

`visit(url)` itself needs nothing beyond the URL — no browser, no consumer
package, no shared state. That is why `src/browser.ts` imports nothing from
the rest of this package: it is a browser, not a mock-aware helper, and the
wiring above is what turns it into one for the duration of a login.

## Mocks are strict by default

Every mock refuses what a real server would refuse, so a client's mistake
shows up as the mock's answer instead of an assertion written by whoever
wrote the mistake:

- **An unregistered `client_id`** is refused directly at `/authorize` (never
  redirected — an unregistered client's `redirect_uri` cannot be trusted
  either).
- **An unregistered `redirect_uri`** is refused the same way, directly and
  never redirected, even for a `client_id` the mock does know. A `UaaClient`
  carries `redirectUris?: string[]`, defaulting to
  `['http://localhost:61001/callback']` — the callback
  `@mcp-abap-adt/auth-providers` uses by default — and the match is exact,
  byte-for-byte string comparison (RFC 6749 §3.1.2.3), never a prefix or
  origin match. Without this a registered `client_id` would carry any
  `redirect_uri` through, including an attacker's — an open redirect — and a
  provider misconfigured with the wrong callback would pass silently instead
  of being refused.
- **`response_type` must be exactly `code`.** Missing or set to anything else
  (`token`, for instance), `/authorize` refuses it. Unlike the two checks
  above, this falls *after* the trust boundary — `client_id` and
  `redirect_uri` are already valid — so per RFC 6749 §4.1.2.1 it is reported
  **at the callback**: a `302` carrying `error` (`invalid_request` when
  absent, `unsupported_response_type` when present but wrong),
  `error_description`, and the mirrored `state`.
- **A wrong or missing client secret** at the token endpoint is refused as
  `invalid_client`, with a `401` + `WWW-Authenticate` when the credentials
  arrived via the `Authorization` header and a `400` when they arrived in the
  body, matching RFC 6749 §5.2 exactly rather than always answering one or
  the other.
- **A code or a refresh token is bound to the client it was issued to.**
  Register two clients and try to redeem the first client's code, or its
  refresh token, while authenticated as the second, and the mock answers
  `invalid_grant` — "the code/refresh token was issued to a different
  client" — even though the credential itself is real and unexpired. This
  rule is implemented once, in `src/clients.ts`, and shared by both the UAA
  and OIDC mocks so they cannot disagree about what "issued to" means.
- **A used or expired authorization code** is refused, as is a
  **`redirect_uri`** that does not match the one used to request the code.
- **The OIDC mock demands PKCE.** `/authorize` refuses a request with no
  `code_challenge`, no `code_challenge_method`, or a method other than
  `S256`. `/token` then verifies the presented `code_verifier` derives the
  challenge. `state` is mirrored back unchanged by default, never judged —
  validating `state` is the client's job, and a mock that checked it would
  hide whether the client does. `startMockOidc({ state: 'wrongState' })` and
  `{ state: 'missingState' }` exist to test that the client notices when a
  server does not behave.
- **Refresh tokens rotate by default** (`rotateRefreshTokens: true`): each
  refresh exchange invalidates the presented token and issues a new one, and
  presenting an already-superseded token is refused as reuse — configurable
  to `false` for servers that hand back the same refresh token indefinitely,
  since both behaviours exist among real UAAs.
- **The SAML bearer grant**
  (`urn:ietf:params:oauth:grant-type:saml2-bearer`) can be `'strict'` (the
  default), `'lenient'`, or `'off'` — see
  [RFC 7522 and `samlBearer: 'strict'`](#rfc-7522-and-samlbearer-strict)
  below.

## Mock UAA (`startMockUaa`)

Authorization code grant at `GET /oauth/authorize` / `POST /oauth/token`,
refresh at the same token endpoint, and the SAML 2.0 bearer grant. Access
tokens are syntactically valid JWTs (`mintJwt`) carrying `exp`/`iat`; nothing
in the family verifies their signature, only the shape and expiry.
`mintExpiredAccessWithValidRefresh()` returns an already-expired access token
paired with a still-valid refresh token, for a refresh test that would
otherwise need to hand-craft a JWT or run a code flow and wait.

## Mock OIDC (`startMockOidc`)

Discovery at `GET /.well-known/openid-configuration`, PKCE demanded at
`/authorize` and verified at `/token`, `state` mirrored (or deliberately
corrupted, see above). Client and redirect_uri binding, client
authentication, and the shape of a callback-reported error are the same
functions the UAA mock uses, from `src/clients.ts` — not a second,
independently-written copy that could quietly disagree.

### What this does and does not prove

The token exchange returns no `id_token`, though OIDC Core §3.1.3.3 requires
one for an `openid`-scoped authorization code exchange — a consumer whose
provider never validates an `id_token` passes silently against this mock.
The discovery document is a deliberate minimum subset — `issuer`,
`authorization_endpoint`, `token_endpoint`,
`code_challenge_methods_supported`, and `response_types_supported` — and
omits `jwks_uri`, `subject_types_supported`, and
`id_token_signing_alg_values_supported`, all three required by OIDC
Discovery §3, so a client using a conformant discovery library would refuse
it. A consumer's `id_token` handling therefore has no judge in this suite;
**live testing against a real OIDC provider remains necessary** and is not
made obsolete by these tests passing.

## Mock SAML IdP (`startMockSamlIdp`)

`GET /sso` turns an HTTP-Redirect-bound `AuthnRequest` into an
auto-submitting HTML form carrying a `samlp:Response`, signed with a fresh,
per-instance, in-memory key pair and certificate (`generateKeyMaterial`,
`signXml`, `certificatePem` on the handle). It never posts to the ACS
itself — only a browser, or `visit()` standing in for one, does that; see
[Quick start](#quick-start-visit-and-the-openurl-seam) above.

### Corruption variants

`startMockSamlIdp({ variant })` and `idp.setVariant(v)` select one of twelve
shapes. Every variant changes exactly one field of an otherwise-valid
response, so a rejection is attributable to that field rather than to an
accumulation of mistakes. The **Verified by** column names what actually
proved each row: `@node-saml/node-saml@5.1.0`'s `validatePostResponseAsync`
where it inspects that field, or "structural (canary)" where it does not —
read directly from the installed library's source
(`src/__tests__/samlVerification.test.ts`), not assumed from its docs.

| Variant | What changes | Verified by |
|---|---|---|
| `valid` | (nothing — the baseline) | node-saml: accepted |
| `unsigned` | no `<Signature>` at all | node-saml: rejected (`Invalid signature`) |
| `wrongKey` | signed with an unrelated key pair | node-saml: rejected (`Invalid signature`) |
| `tamperedAfterSign` | signed content mutated after signing | node-saml: rejected (`Invalid signature`) |
| `expired` | `NotOnOrAfter` in the past | node-saml: rejected |
| `notYetValid` | `NotBefore` in the future | node-saml: rejected |
| `wrongAudience` | `Audience` does not match | node-saml: rejected |
| `wrongInResponseTo` | `InResponseTo` names no live request | node-saml: rejected |
| `statusFailure` | `<samlp:Status>` reports failure | **structural (canary)** — see below |
| `wrongIssuer` | `Issuer` does not match | **structural (canary)** — see below |
| `wrongDestination` | `Response@Destination` does not match the ACS | **structural (canary)** — see below |
| `wrongRecipient` | `SubjectConfirmationData@Recipient` does not match the ACS | **structural (canary)** — see below |

**Four of the twelve rows have no independent judge here**, for two distinct
reasons, both confirmed by reading `node_modules/@node-saml/node-saml`'s
source rather than assumed from its documentation:

- `wrongDestination` and `wrongRecipient` — node-saml's response validation
  never reads `Destination` or `Recipient` at all. Its source shows
  `Recipient` does not occur outside test fixtures, and `Destination` occurs
  only in the code that *builds* an outgoing request, never in the code that
  *validates* an incoming response.
- `statusFailure` and `wrongIssuer` — node-saml only reads the top-level
  `<samlp:Status>` inside the branch guarded by `if (!("Assertion" in
  response))` — that is, whenever *any* `Assertion` element is present in
  the response at all, signed or not, not specifically because it is
  validly signed — and only compares `idpIssuer` against the message on the
  **logout** path (`verifyIssuer`, called from `verifyLogoutRequest` /
  `verifyLogoutResponse`), never from `validatePostResponseAsync`. A
  Responder-failure status or a forged issuer riding alongside an Assertion
  is accepted outright on this path.

All four are asserted **structurally** instead (the corrupted field is
present and differs from `valid`, and the verifier resolves rather than
rejects) and pinned as **canaries**: if a future version of node-saml starts
checking one of them, the corresponding test in
`src/__tests__/samlVerification.test.ts` will start failing — signalling
"this field is judged now," not a defect in the mock. Until then, a mock IdP
that gets any of these four fields wrong has no automated judge in this
suite at all; only a live test against a relying party that enforces its
own checks on these fields would catch it.

### Replay: a sequence, not a variant

A replayed SAML assertion is, in isolation, perfectly valid — that is
exactly why replay is dangerous, and exactly why no off-the-shelf verifier
rejects one on sight. Remembering which assertion IDs have already been
consumed is the relying party's job, not the identity provider's, so this
package cannot offer "the replay variant" the way it offers `wrongAudience`
or `expired`. What it offers instead is the two-step shape that *makes*
replay dangerous:

```ts
const idp = await startMockSamlIdp();
// ... deliver an assertion once ...
idp.repeatLastAssertion(); // one-shot: reuses the previous assertion's ID next time
// ... deliver again ...
```

Both deliveries are individually valid and share one assertion ID. A
verifier that has never seen the first one accepts the second exactly as
readily — which is the point: nothing in the second message is malformed,
so only a relying party that remembers assertion IDs it has already
consumed can catch the replay. This package proves the two deliveries are
indistinguishable to a naive verifier rather than pretending to detect the
replay itself — that detection is exactly what a consuming package's own
validation strategy is responsible for building and is what this mock exists
to let it be tested against.

There is a trap immediately next door that looks like replay detection but
is not: node-saml's *request*-ID cache is one-shot (`removeAsync` on
`InResponseTo` after a successful validation), so a **second, freshly-minted**
assertion answering the same, already-consumed `AuthnRequest` is rejected
too — for a reason that has nothing to do with the assertion ID repeating.
`src/__tests__/samlVerification.test.ts` covers this with a *fresh* second
assertion specifically so the rejection cannot be mistaken for replay
detection.

### RFC 7522 and `samlBearer: 'strict'`

`startMockUaa({ samlBearer: 'strict' })` (the default) enforces RFC 7522
§2.1: the `assertion` parameter of the SAML 2.0 bearer grant must be a
**base64url**-encoded (no `+`, `/`, or padding) **`<saml:Assertion>`** as the
document's own root element — not a `<samlp:Response>` wrapping one, and not
base64 with the standard alphabet.

This surfaced a real finding about a consumer rather than about the mock:
`exchangeSamlAssertion` in `@mcp-abap-adt/auth-providers` currently sends a
**base64** `samlp:Response`, not a base64url `Assertion`. Against
`samlBearer: 'strict'`, that request is refused. `samlBearer: 'lenient'`
accepts whatever a real, permissive UAA might accept without enforcing the
RFC's document-shape requirement, and `samlBearer: 'off'` refuses the grant
outright (`unsupported_grant_type`), for testing a server that never enabled
it. Use `'strict'` to hold a client to the RFC; use `'lenient'` or `'off'`
only to reproduce a specific real server's looser or absent behaviour —
reaching for `'lenient'` just to make a non-conformant client's test pass
would hide the same finding this package exists to surface.

## What signature verification here does and does not prove

`src/signing.ts` generates a fresh, in-memory, self-signed certificate per
mock instance and signs SAML assertions with XML-DSig via `xml-crypto`. Its
own test suite (`src/__tests__/signing.test.ts`) exists to prove the
signature is real — bound to the content and to the private key — not to
prove the mock IdP is a faithful stand-in for a real one. Concretely:

- The package's own tests verify a signature with `xml-crypto` — the same
  library that produced it. A canonicalisation or signing bug shared between
  producing and checking the signature would not be caught here.
- `@node-saml/node-saml`, used elsewhere in this family's test suites,
  independently checks signature validity, `Conditions` timestamps and
  `Audience` at the SAML-profile level — but it shares `xml-crypto`
  underneath for the actual cryptography, so it is not an independent
  implementation of XML-DSig either.
- As detailed in [Corruption variants](#corruption-variants) above, it
  checks **none of `Destination`, `SubjectConfirmationData@Recipient`, the
  top-level `<samlp:Status>`, or the Assertion's `Issuer`** on the response
  path this suite exercises, so a mock IdP that gets any of those four
  wrong has no judge in this suite.
- It has **no assertion-ID replay cache** — replaying a captured assertion is
  not something this package or `@node-saml/node-saml` will flag; replay
  detection is the relying party's responsibility (see
  [Replay: a sequence, not a variant](#replay-a-sequence-not-a-variant)
  above).
- None of the above proves canonicalisation matches what a real identity
  provider produces. A green suite here is evidence the mock's own signature
  round-trips and that an independent library accepts what it should and
  rejects what it checks, not evidence the mock's SAML profile matches a
  live IdP byte-for-byte. **Live testing against a real identity provider
  remains necessary** and is not made obsolete by these tests passing.
